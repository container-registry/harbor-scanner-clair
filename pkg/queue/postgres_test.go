package queue

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/postgres"
	"github.com/container-registry/harbor-scanner-clair/pkg/scan"
)

// newTestQueue gives each test its own schema rather than a shared table: this
// package and the store's own tests run in parallel against the same database.
func newTestQueue(t *testing.T, concurrency int, deadlines Deadlines, controller scan.Controller) (Enqueuer, Worker, *postgres.Store) {
	t.Helper()
	store := newTestStore(t)
	enq, w := NewPostgresQueue(etc.JobQueue{WorkerConcurrency: concurrency}, deadlines, store, controller)
	return enq, w, store
}

func newTestStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("SCANNER_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("SCANNER_TEST_POSTGRES_URL is not set; run `task test:postgres` to start one")
	}
	ctx := context.Background()

	schema := testSchemaName(t)
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %q", schema))
	require.NoError(t, err)
	require.NoError(t, admin.Close(ctx))

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		pool.Close()
		cleanup, cErr := pgx.Connect(context.Background(), dsn)
		if cErr != nil {
			return
		}
		defer cleanup.Close(context.Background())
		_, _ = cleanup.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA %q CASCADE", schema))
	})

	store, err := postgres.New(ctx, pool, postgres.Config{ScanJobTTL: time.Hour})
	require.NoError(t, err)
	return store
}

// schemaSeq keeps the generated names unique even when two tests share a
// prefix: identifiers are capped at 63 bytes, so the readable part is truncated.
var schemaSeq atomic.Int64

func testSchemaName(t *testing.T) string {
	t.Helper()
	name := make([]rune, 0, 30)
	for _, r := range t.Name() {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			name = append(name, r)
		case r >= 'A' && r <= 'Z':
			name = append(name, r+('a'-'A'))
		default:
			name = append(name, '_')
		}
		if len(name) == 30 {
			break
		}
	}
	return fmt.Sprintf("q%d_%d_%s", os.Getpid(), schemaSeq.Add(1), string(name))
}

// TestRunJobBoundsScanByDeadline proves the whole job is bounded, and bounded by
// the shorter of the two: Start receives context.Background() from main, so an
// unbounded registry or Clair call would wedge the (single) worker goroutine
// forever, and a deadline as long as the row lock would let a worker outlive the
// claim that keeps a second worker off the job. It needs no database.
func TestRunJobBoundsScanByDeadline(t *testing.T) {
	const jobDeadline = 90 * time.Second
	ctrl := &capturingController{}
	w := &pgWorker{
		deadlines:  Deadlines{LockTTL: jobDeadline + 30*time.Second, JobDeadline: jobDeadline},
		controller: ctrl,
	}

	before := time.Now()
	w.runJob(context.Background(), &postgres.Claim{ID: "job-1", Attempts: 1})

	require.True(t, ctrl.gotDeadline, "Scan must receive a context with a deadline (an unbounded call would otherwise wedge the worker)")
	remaining := time.Until(ctrl.deadline)
	assert.Greater(t, remaining, jobDeadline-5*time.Second, "deadline must be ~JobDeadline out")
	assert.LessOrEqual(t, remaining, jobDeadline, "deadline must not exceed JobDeadline")
	assert.WithinDuration(t, before.Add(jobDeadline), ctrl.deadline, 5*time.Second)
}

type capturingController struct {
	gotDeadline bool
	deadline    time.Time
}

func (c *capturingController) Scan(ctx context.Context, _ string, _ harbor.ScanRequest) error {
	c.deadline, c.gotDeadline = ctx.Deadline()
	return nil
}

// TestEnqueueBeforeWorkerStartsStillRuns is the regression pin for the move off
// an in-process worker pool. Nothing outside the process held the job, so a scan
// accepted during a restart was silently lost: the record stayed Queued and
// Harbor 302-polled it until the TTL. A row waits.
func TestEnqueueBeforeWorkerStartsStillRuns(t *testing.T) {
	ctrl := &countingController{}
	enq, w, store := newTestQueue(t, 1, testDeadlines(time.Minute), ctrl)

	id, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err)

	// No worker was running at enqueue time; start one only now.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 20*time.Second, 20*time.Millisecond,
		"a job enqueued while no worker was listening must still be picked up")
	assert.Equal(t, id, ctrl.ids[0])

	got, err := store.Get(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, job.Pending, got.Status, "the claim must move the record out of Queued")
}

// TestQueueIsFIFO pins that the oldest job runs first. Claiming the newest first
// would starve the oldest scan indefinitely under a steady arrival rate, and
// Harbor polls it until the TTL. Single worker, so the order observed is the
// order claimed.
func TestQueueIsFIFO(t *testing.T) {
	const jobs = 10
	ctrl := &countingController{}
	enq, w, _ := newTestQueue(t, 1, testDeadlines(time.Minute), ctrl)

	ids := make([]string, 0, jobs)
	for range jobs {
		id, err := enq.Enqueue(context.Background(), scanRequest())
		require.NoError(t, err)
		ids = append(ids, id)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == jobs }, 30*time.Second, 20*time.Millisecond)

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	assert.Equal(t, ids, ctrl.ids, "jobs were claimed out of order (the queue is not FIFO)")
}

// TestEachJobRunsOnce pins SKIP LOCKED under concurrency: several workers claim
// from the same table at the same time, and no job may be handed to two of them.
func TestEachJobRunsOnce(t *testing.T) {
	const jobs = 20
	ctrl := &countingController{}
	enq, w, _ := newTestQueue(t, 4, testDeadlines(time.Minute), ctrl)

	for range jobs {
		_, err := enq.Enqueue(context.Background(), scanRequest())
		require.NoError(t, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == jobs }, 30*time.Second, 20*time.Millisecond)

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	seen := make(map[string]int, jobs)
	for _, id := range ctrl.ids {
		seen[id]++
	}
	assert.Len(t, seen, jobs, "every job must run exactly once")
	for id, n := range seen {
		assert.Equal(t, 1, n, "job %s ran %d times", id, n)
	}
}

// TestInFlightJobSurvivesWorkerCrash pins the crash-recovery path. A worker
// killed mid-scan (OOM, SIGKILL) leaves its row claimed; once the lock expires
// another worker must pick the job up rather than leaving Harbor to poll a
// record nobody will ever touch again.
func TestInFlightJobSurvivesWorkerCrash(t *testing.T) {
	ctrl := &countingController{}
	// A lock TTL in the past is exactly the state a killed worker leaves behind,
	// without the test having to wait for one to expire.
	enq, w, store := newTestQueue(t, 1, testDeadlines(time.Minute), ctrl)

	id, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err)

	crashed, err := store.Claim(context.Background(), -time.Second)
	require.NoError(t, err)
	require.NotNil(t, crashed, "the doomed worker must have claimed the job")
	require.Equal(t, id, crashed.ID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 20*time.Second, 20*time.Millisecond,
		"a job left claimed by a crashed worker must be reclaimed and run")
	assert.Equal(t, id, ctrl.ids[0])
}

// TestStopIsBoundedWhileScanning pins that SIGTERM is not held hostage by an
// in-flight scan. Stop() waits on the worker WaitGroup, and a worker mid-scan
// does not return to its loop until the job finishes -- up to the full job
// deadline. Without a bound, shutdown stalls until the orchestrator SIGKILLs.
func TestStopIsBoundedWhileScanning(t *testing.T) {
	ctrl := &blockingController{started: make(chan struct{}), release: make(chan struct{})}
	// A deadline an hour out: without the Stop() bound the test would hang here.
	enq, w, _ := newTestQueue(t, 1, Deadlines{LockTTL: 2 * time.Hour, JobDeadline: time.Hour}, ctrl)

	_, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	select {
	case <-ctrl.started:
	case <-time.After(20 * time.Second):
		t.Fatal("scan never started")
	}

	done := make(chan struct{})
	go func() { w.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopTimeout + 15*time.Second):
		t.Fatal("Stop() did not return within its own timeout while a scan was in flight")
	}
	close(ctrl.release)
}

// TestDepthCountsWaitingJobs backs the queue_depth gauge. Depth is what tells an
// operator that scans are late because the worker pool is saturated rather than
// because any individual scan is slow.
func TestDepthCountsWaitingJobs(t *testing.T) {
	// No worker started, so nothing is claimed and every job stays waiting.
	enq, w, _ := newTestQueue(t, 1, testDeadlines(time.Minute), &countingController{})
	for range 3 {
		_, err := enq.Enqueue(context.Background(), scanRequest())
		require.NoError(t, err)
	}

	depth, err := w.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)
}

// TestQueueWaitIsObserved pins that the wait is measured from enqueue, not from
// pickup. Measuring the scan alone hides the case this metric exists for: a fast
// scan that Harbor still abandons because the job waited first.
func TestQueueWaitIsObserved(t *testing.T) {
	ctrl := &countingController{}
	enq, w, _ := newTestQueue(t, 1, testDeadlines(time.Minute), ctrl)

	_, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err)

	before := observationCount(t, metrics.QueueWaitSeconds)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 20*time.Second, 10*time.Millisecond)
	assert.Eventually(t, func() bool { return observationCount(t, metrics.QueueWaitSeconds) == before+1 },
		5*time.Second, 10*time.Millisecond)
}
