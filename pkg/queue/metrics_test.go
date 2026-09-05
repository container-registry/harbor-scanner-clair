package queue

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
)

func TestInProcessDepthCountsWaitingJobs(t *testing.T) {
	enq, w := NewInProcessQueue(
		etc.JobQueue{WorkerConcurrency: 1},
		testDeadlines(time.Minute), memory.NewStore(), &countingController{},
	)
	for range 3 {
		_, err := enq.Enqueue(context.Background(), scanRequest())
		require.NoError(t, err)
	}

	depth, err := w.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)
}

// TestQueueWaitSkipsJobsWithoutTimestamp covers a job whose enqueue time is
// unknown: reporting a wait measured from the epoch would wreck the histogram
// permanently.
func TestQueueWaitSkipsJobsWithoutTimestamp(t *testing.T) {
	before := observationCount(t, metrics.QueueWaitSeconds)
	observeQueueWait(time.Time{})
	assert.Equal(t, before, observationCount(t, metrics.QueueWaitSeconds))
}

func observationCount(t *testing.T, obs prometheus.Observer) uint64 {
	t.Helper()
	m, ok := obs.(prometheus.Metric)
	require.True(t, ok, "observer must be collectable")
	var pb dto.Metric
	require.NoError(t, m.Write(&pb))
	return pb.GetHistogram().GetSampleCount()
}

// TestUndispatchedJobIsMarkedFailed pins that a job whose store record was
// created but whose dispatch then failed does not sit at Queued. Queued is
// indistinguishable from "waiting for a worker", so Harbor polled such a job
// until the TTL instead of being told the real cause.
func TestUndispatchedJobIsMarkedFailed(t *testing.T) {
	store := memory.NewStore()
	var dispatched string
	enq := &enqueuer{
		store: store,
		dispatch: func(_ context.Context, j Job) error {
			dispatched = j.ID
			return errors.New("transport down")
		},
	}

	_, err := enq.Enqueue(context.Background(), scanRequest())
	require.Error(t, err)
	require.NotEmpty(t, dispatched, "dispatch must have been attempted")

	got, err := store.Get(context.Background(), dispatched)
	require.NoError(t, err)
	require.NotNil(t, got, "the record is created before dispatch, so it exists")
	assert.Equal(t, job.Failed, got.Status, "an undispatched job must not be left Queued")
	assert.Contains(t, got.Error, "transport down")
}

// TestUndispatchedCleanupSurvivesACanceledContext pins the detached write. The
// usual reason a dispatch fails is that the request context is already done, and
// reusing it made the cleanup fail for exactly the same reason -- leaving the
// record at Queued, which is the state this path exists to avoid.
func TestUndispatchedCleanupSurvivesACanceledContext(t *testing.T) {
	store := memory.NewStore()
	var dispatched string

	ctx, cancel := context.WithCancel(context.Background())
	enq := &enqueuer{
		store: ctxStore{Store: store},
		dispatch: func(dctx context.Context, j Job) error {
			dispatched = j.ID
			cancel() // the request went away mid-dispatch
			return dctx.Err()
		},
	}

	_, err := enq.Enqueue(ctx, scanRequest())
	require.Error(t, err)
	require.NotEmpty(t, dispatched)

	got, err := store.Get(context.Background(), dispatched)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Failed, got.Status, "the cleanup must not inherit the dead context")
}

// ctxStore rejects writes on an expired context, the way a database driver does.
// The memory store ignores ctx, so it cannot exercise the detached write on its
// own.
type ctxStore struct {
	persistence.Store
}

func (s ctxStore) FailIfQueued(ctx context.Context, scanJobID, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.FailIfQueued(ctx, scanJobID, msg)
}
