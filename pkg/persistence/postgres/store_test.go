package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
)

const testJobID = "abc123"

// TestStatusLiteralsMatchTheJobIota needs no database: it pins the one thing the
// SQL cannot express safely. The statements and the index predicate spell the
// status values as literals, so a reordered iota in pkg/job would silently make
// every WHERE clause mean something else.
func TestStatusLiteralsMatchTheJobIota(t *testing.T) {
	assert.Equal(t, int16(0), statusQueued)
	assert.Equal(t, int16(1), statusPending)
	assert.Equal(t, int16(2), statusFinished)
	assert.Equal(t, int16(3), statusFailed)
}

// newTestStore gives each test its own schema rather than a shared table: the
// store and queue test packages run in parallel against the same database, so
// truncating a shared table would have them delete each other's rows.
func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	pool := newTestPool(t)
	store, err := New(context.Background(), pool, Config{ScanJobTTL: time.Hour})
	require.NoError(t, err)
	return store, pool
}

func newTestPool(t *testing.T) *pgxpool.Pool {
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
	return pool
}

// schemaSeq keeps the generated names unique even when two tests share a
// prefix: identifiers are capped at 63 bytes, so the readable part is truncated.
var schemaSeq atomic.Int64

// testSchemaName is derived from the test name and the pid so a schema left
// behind by a killed run is recognizable, and two packages running in parallel
// cannot collide.
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
	return fmt.Sprintf("t%d_%d_%s", os.Getpid(), schemaSeq.Add(1), string(name))
}

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "http://core:8080", Authorization: "Bearer token"},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
}

func queuedJob(id string) job.ScanJob {
	return job.ScanJob{ID: id, Status: job.Queued, Request: scanRequest()}
}

// expire ages a record out without waiting for a TTL, so the expiry cases are
// deterministic instead of timing-dependent.
func expire(t *testing.T, pool *pgxpool.Pool, ids ...string) {
	t.Helper()
	for _, id := range ids {
		_, err := pool.Exec(context.Background(),
			`UPDATE scan_job SET expires_at = now() - interval '1 second' WHERE id = $1`, id)
		require.NoError(t, err)
	}
}

// age backdates created_at so claim ordering is asserted on a known order
// rather than on how fast the inserts happened to run.
func age(t *testing.T, pool *pgxpool.Pool, id string, seconds int) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE scan_job SET created_at = now() - make_interval(secs => $2) WHERE id = $1`, id, seconds)
	require.NoError(t, err)
}

// bigReport is repetitive the way a real vulnerability report is.
func bigReport(items int) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteString(`{"generated_at":"2026-09-05T00:00:00Z","severity":"High","vulnerabilities":[`)
	for i := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"id":"CVE-2026-%04d","package":"libexample-%d","version":"1.2.%d","severity":"High","description":"An example vulnerability"}`,
			i, i, i)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func TestCreateAndGet(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))

	got, err := s.Get(ctx, testJobID)
	require.NoError(t, err)
	require.NotNil(t, got, "Harbor polls immediately after the 202; the Queued record must already exist")
	assert.Equal(t, job.Queued, got.Status)
	assert.Empty(t, got.Error)
	assert.Empty(t, got.Report)
}

func TestGetMissingReturnsNil(t *testing.T) {
	s, _ := newTestStore(t)
	got, err := s.Get(context.Background(), "nope")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestCreateDoesNotOverwriteAnExistingRecord keeps the SetNX semantics the
// Redis store had: a repeated id must not reset a record a worker is acting on.
func TestCreateDoesNotOverwriteAnExistingRecord(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))
	require.NoError(t, s.UpdateStatus(ctx, testJobID, job.Pending))
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))

	got, err := s.Get(ctx, testJobID)
	require.NoError(t, err)
	assert.Equal(t, job.Pending, got.Status, "a second Create must not reset a job already being run")
}

func TestFinishStoresReportAndStatus(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))
	require.NoError(t, s.UpdateStatus(ctx, testJobID, job.Pending))

	report := bigReport(500)
	require.NoError(t, s.Finish(ctx, testJobID, report))

	got, err := s.Get(ctx, testJobID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)
	assert.JSONEq(t, string(report), string(got.Report))
	assert.Empty(t, got.Error)

	// The column holds the compressed bytes, not the JSON: that is what the
	// table carries for the whole TTL and re-reads on every Harbor poll.
	var stored []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT report FROM scan_job WHERE id = $1`, testJobID).Scan(&stored))
	t.Logf("raw=%d bytes stored=%d bytes", len(report), len(stored))
	assert.Less(t, len(stored), len(report)/4, "the stored report must be compressed")
}

// TestTerminalWritesDoNotOverwriteEachOther is the race the read-modify-write
// Redis store could not close. A worker that finished and a cleanup path that decided the job
// failed can both be in flight; whichever loses must leave the record alone
// rather than replacing a real report with an error, or vice versa.
func TestTerminalWritesDoNotOverwriteEachOther(t *testing.T) {
	ctx := context.Background()

	t.Run("failed cannot overwrite finished", func(t *testing.T) {
		s, _ := newTestStore(t)
		require.NoError(t, s.Create(ctx, queuedJob("f1")))
		require.NoError(t, s.UpdateStatus(ctx, "f1", job.Pending))
		report := json.RawMessage(`{"severity":"Low"}`)
		require.NoError(t, s.Finish(ctx, "f1", report))

		err := s.UpdateStatus(ctx, "f1", job.Failed, "late failure")
		require.ErrorIs(t, err, persistence.ErrJobNotFound)

		got, err := s.Get(ctx, "f1")
		require.NoError(t, err)
		assert.Equal(t, job.Finished, got.Status)
		assert.JSONEq(t, string(report), string(got.Report))
	})

	t.Run("finished cannot overwrite failed", func(t *testing.T) {
		s, _ := newTestStore(t)
		require.NoError(t, s.Create(ctx, queuedJob("f2")))
		require.NoError(t, s.UpdateStatus(ctx, "f2", job.Pending))
		require.NoError(t, s.UpdateStatus(ctx, "f2", job.Failed, "clair is down"))

		err := s.Finish(ctx, "f2", json.RawMessage(`{"severity":"None"}`))
		require.ErrorIs(t, err, persistence.ErrJobNotFound)

		got, err := s.Get(ctx, "f2")
		require.NoError(t, err)
		assert.Equal(t, job.Failed, got.Status)
		assert.Equal(t, "clair is down", got.Error)
	})
}

// TestExpiredRecordIsGone keeps the guarantee the Redis TTL gave: a job whose
// record aged out during a long scan must not be resurrected by the terminal
// write, or Harbor would poll a record no worker will ever touch again.
func TestExpiredRecordIsGone(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))
	require.NoError(t, s.UpdateStatus(ctx, testJobID, job.Pending))
	expire(t, pool, testJobID)

	require.ErrorIs(t, s.Finish(ctx, testJobID, json.RawMessage(`{}`)), persistence.ErrJobNotFound)
	require.ErrorIs(t, s.UpdateStatus(ctx, testJobID, job.Failed, "too late"), persistence.ErrJobNotFound)

	got, err := s.Get(ctx, testJobID)
	require.NoError(t, err)
	assert.Nil(t, got, "an expired job must not be resurrected by a terminal write")
}

// TestFailIfQueuedOnlyClaimsQueuedRecords pins the enqueue-cleanup contract: a
// dispatch failure races the worker, and the cleanup must never overwrite a
// record the worker has moved past Queued.
func TestFailIfQueuedOnlyClaimsQueuedRecords(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	t.Run("still queued: claimed as failed", func(t *testing.T) {
		require.NoError(t, s.Create(ctx, queuedJob("q1")))
		require.NoError(t, s.FailIfQueued(ctx, "q1", "could not be queued"))
		got, err := s.Get(ctx, "q1")
		require.NoError(t, err)
		assert.Equal(t, job.Failed, got.Status)
		assert.Contains(t, got.Error, "could not be queued")
	})

	t.Run("worker already finished: left untouched", func(t *testing.T) {
		report := json.RawMessage(`{"severity":"Low"}`)
		require.NoError(t, s.Create(ctx, queuedJob("q2")))
		require.NoError(t, s.UpdateStatus(ctx, "q2", job.Pending))
		require.NoError(t, s.Finish(ctx, "q2", report))
		require.NoError(t, s.FailIfQueued(ctx, "q2", "could not be queued"))
		got, err := s.Get(ctx, "q2")
		require.NoError(t, err)
		assert.Equal(t, job.Finished, got.Status, "a terminal record must never be overwritten by enqueue cleanup")
		assert.JSONEq(t, string(report), string(got.Report))
	})

	t.Run("worker already running: left untouched", func(t *testing.T) {
		require.NoError(t, s.Create(ctx, queuedJob("q3")))
		require.NoError(t, s.UpdateStatus(ctx, "q3", job.Pending))
		require.NoError(t, s.FailIfQueued(ctx, "q3", "could not be queued"))
		got, err := s.Get(ctx, "q3")
		require.NoError(t, err)
		assert.Equal(t, job.Pending, got.Status)
	})

	t.Run("missing record: ErrJobNotFound", func(t *testing.T) {
		err := s.FailIfQueued(ctx, "missing", "could not be queued")
		require.ErrorIs(t, err, persistence.ErrJobNotFound)
	})
}

// TestClaimTakesTheOldestFirst pins FIFO. Claiming the newest first would starve
// the oldest scan indefinitely under a steady arrival rate, and Harbor polls it
// until the TTL.
func TestClaimTakesTheOldestFirst(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	for i, id := range []string{"newest", "middle", "oldest"} {
		require.NoError(t, s.Create(ctx, queuedJob(id)))
		age(t, pool, id, (i+1)*60)
	}

	for _, want := range []string{"oldest", "middle", "newest"} {
		claim, err := s.Claim(ctx, time.Minute)
		require.NoError(t, err)
		require.NotNil(t, claim)
		assert.Equal(t, want, claim.ID)
		assert.Equal(t, 1, claim.Attempts)
		assert.Equal(t, scanRequest(), claim.Request, "the claim must carry everything the scan needs")
	}

	claim, err := s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.Nil(t, claim, "an empty queue is not an error")
}

// TestClaimSkipsRowsLockedByAnotherClaimer is what lets several workers and
// several replicas claim at once. Without SKIP LOCKED the second claimer would
// block on the first one's row lock instead of taking the next job.
func TestClaimSkipsRowsLockedByAnotherClaimer(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob("first")))
	age(t, pool, "first", 120)
	require.NoError(t, s.Create(ctx, queuedJob("second")))
	age(t, pool, "second", 60)

	// Hold the head of the queue the way a concurrent claimer's transaction does.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	var locked string
	require.NoError(t, tx.QueryRow(ctx, `SELECT id FROM scan_job WHERE id = 'first' FOR UPDATE`).Scan(&locked))

	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	claim, err := s.Claim(claimCtx, time.Minute)
	require.NoError(t, err, "a claim must skip a locked row, not queue behind it")
	require.NotNil(t, claim)
	assert.Equal(t, "second", claim.ID)
}

// TestClaimReclaimsAfterTheLockExpires is the crash-recovery path: a worker
// killed mid-scan leaves its row Pending and locked, and nothing else would ever
// run it. Once locked_until passes, the job is runnable again and the attempt
// count is the evidence it was retried.
func TestClaimReclaimsAfterTheLockExpires(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))

	// A lock that is already in the past is the same state a killed worker
	// leaves behind, without the test having to wait for one.
	first, err := s.Claim(ctx, -time.Second)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, 1, first.Attempts)

	second, err := s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, second, "a job whose lock expired must be claimable again")
	assert.Equal(t, testJobID, second.ID)
	assert.Equal(t, 2, second.Attempts)

	third, err := s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.Nil(t, third, "a job still under an unexpired lock must not be handed out twice")
}

func TestClaimIgnoresTerminalAndExpiredJobs(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Create(ctx, queuedJob("done")))
	require.NoError(t, s.UpdateStatus(ctx, "done", job.Pending))
	require.NoError(t, s.Finish(ctx, "done", json.RawMessage(`{}`)))

	require.NoError(t, s.Create(ctx, queuedJob("failed")))
	require.NoError(t, s.UpdateStatus(ctx, "failed", job.Failed, "nope"))

	require.NoError(t, s.Create(ctx, queuedJob("stale")))
	expire(t, pool, "stale")

	claim, err := s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	assert.Nil(t, claim)
}

func TestSweepDeletesOnlyExpiredJobs(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob("live")))
	require.NoError(t, s.Create(ctx, queuedJob("stale")))
	expire(t, pool, "stale")

	deleted, err := s.Sweep(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	var remaining int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM scan_job`).Scan(&remaining))
	assert.Equal(t, int64(1), remaining)
}

// TestDepthCountsOnlyWaitingJobs backs the queue_depth gauge: it must report
// what is waiting for a worker, not what is running or already done.
func TestDepthCountsOnlyWaitingJobs(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"w1", "w2", "w3"} {
		require.NoError(t, s.Create(ctx, queuedJob(id)))
	}
	depth, err := s.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)

	_, err = s.Claim(ctx, time.Minute)
	require.NoError(t, err)
	depth, err = s.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), depth, "a claimed job is running, not waiting")
}

// TestDDLIsIdempotent covers the deployment: every replica runs the schema at
// startup, and a restart runs it again over a table full of live records.
func TestDDLIsIdempotent(t *testing.T) {
	s, pool := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, queuedJob(testJobID)))

	again, err := New(ctx, pool, Config{ScanJobTTL: time.Hour})
	require.NoError(t, err)

	got, err := again.Get(ctx, testJobID)
	require.NoError(t, err)
	require.NotNil(t, got, "re-applying the schema must not disturb existing records")
	require.NoError(t, again.Ping(ctx))
}
