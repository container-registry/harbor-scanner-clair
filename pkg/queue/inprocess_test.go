package queue

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
)

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080", Authorization: "Bearer token"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
}

// testDeadlines keeps the production relation between the two: the job deadline
// is always the shorter one.
func testDeadlines(lockTTL time.Duration) Deadlines {
	return Deadlines{LockTTL: lockTTL, JobDeadline: lockTTL / 2}
}

// countingController records every job id it is asked to scan.
type countingController struct {
	mu  sync.Mutex
	ids []string
}

func (c *countingController) Scan(_ context.Context, jobID string, _ harbor.ScanRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids = append(c.ids, jobID)
	return nil
}

func (c *countingController) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids)
}

// blockingController parks inside Scan until released, but honors ctx
// cancellation the way controller.Scan does through its outbound calls.
type blockingController struct {
	startOnce sync.Once
	started   chan struct{}
	release   chan struct{}
}

func (c *blockingController) Scan(ctx context.Context, _ string, _ harbor.ScanRequest) error {
	c.startOnce.Do(func() { close(c.started) })
	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return nil
}

// TestInProcessQueueRunsTheScan is the regression pin for the memory backend.
// A Postgres enqueuer built around a nil store panics on the first scan, and a
// conditional worker leaves nobody to consume: an adapter that comes up healthy
// and cannot run a single scan is what this pair prevents.
func TestInProcessQueueRunsTheScan(t *testing.T) {
	store := memory.NewStore()
	ctrl := &countingController{}
	enq, w := NewInProcessQueue(
		etc.JobQueue{WorkerConcurrency: 1},
		testDeadlines(time.Minute), store, ctrl,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	t.Cleanup(w.Stop)

	id, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err, "enqueue must not panic or error under the memory backend")
	require.NotEmpty(t, id)

	require.Eventually(t, func() bool { return ctrl.count() == 1 }, 10*time.Second, 10*time.Millisecond,
		"the in-process worker must actually run the enqueued scan")

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	assert.Equal(t, id, ctrl.ids[0])
}

// TestInProcessQueueCreatesTheJobRecord proves the poll-side contract holds too:
// the store record Harbor polls exists as soon as Enqueue returns, so the report
// endpoint answers 302 rather than 404 before the worker gets to it.
func TestInProcessQueueCreatesTheJobRecord(t *testing.T) {
	store := memory.NewStore()
	// No worker started: the record must be there on Enqueue alone.
	enq, _ := NewInProcessQueue(
		etc.JobQueue{WorkerConcurrency: 1},
		testDeadlines(time.Minute), store, &countingController{},
	)

	id, err := enq.Enqueue(context.Background(), scanRequest())
	require.NoError(t, err)

	got, err := store.Get(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, got, "Harbor polls immediately after the 202; the Queued record must already exist")
	assert.Equal(t, job.Queued, got.Status)
	assert.Equal(t, scanRequest(), got.Request, "the record must carry the request the worker needs")
}

// TestInProcessQueueRejectsWhenFull pins that a full backlog fails the enqueue
// instead of blocking the HTTP handler past Harbor's 5s client timeout.
func TestInProcessQueueRejectsWhenFull(t *testing.T) {
	store := memory.NewStore()
	// No worker consuming, so the channel fills and stays full.
	enq, _ := NewInProcessQueue(
		etc.JobQueue{WorkerConcurrency: 1},
		testDeadlines(time.Minute), store, &countingController{},
	)

	var lastErr error
	for range inProcessBacklog + 5 {
		if _, err := enq.Enqueue(context.Background(), scanRequest()); err != nil {
			lastErr = err
			break
		}
	}
	require.Error(t, lastErr, "a full in-process backlog must fail fast, not block the handler")
	assert.Contains(t, lastErr.Error(), "full")
}
