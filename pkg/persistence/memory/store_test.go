package memory

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/job"
)

const jobID = "id1"

func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	// Unknown -> nil, nil.
	got, err := s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, s.Create(ctx, job.ScanJob{ID: jobID, Status: job.Queued}))

	require.NoError(t, s.UpdateStatus(ctx, jobID, job.Pending))
	got, err = s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, job.Pending, got.Status)

	report := json.RawMessage(`{"severity":"None"}`)
	require.NoError(t, s.Finish(ctx, jobID, report))

	got, err = s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status)
	assert.JSONEq(t, string(report), string(got.Report))

	// Create is SetNX: does not overwrite.
	require.NoError(t, s.Create(ctx, job.ScanJob{ID: jobID, Status: job.Queued}))
	got, err = s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status)
}

func TestMemoryStoreUpdateMissing(t *testing.T) {
	s := NewStore()
	require.Error(t, s.UpdateStatus(context.Background(), jobID, job.Finished))
	require.Error(t, s.Finish(context.Background(), jobID, json.RawMessage(`{}`)))
	require.Error(t, s.FailIfQueued(context.Background(), jobID, "boom"))
}

// TestMemoryStoreFailIfQueued mirrors the Postgres contract: only a Queued
// record may be claimed as Failed by enqueue cleanup.
func TestMemoryStoreFailIfQueued(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	require.NoError(t, s.Create(ctx, job.ScanJob{ID: jobID, Status: job.Queued}))
	require.NoError(t, s.FailIfQueued(ctx, jobID, "undispatched"))
	got, err := s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, job.Failed, got.Status)

	require.NoError(t, s.UpdateStatus(ctx, jobID, job.Finished))
	require.NoError(t, s.FailIfQueued(ctx, jobID, "undispatched"))
	got, err = s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, job.Finished, got.Status, "a non-Queued record must be left untouched")
}

// TestGetReturnsAnIndependentReport pins that the returned record does not alias
// the stored one. A struct copy still shares json.RawMessage's backing array, so
// a caller writing through the returned report corrupted the store.
func TestGetReturnsAnIndependentReport(t *testing.T) {
	s := NewStore()
	ctx := context.Background()
	require.NoError(t, s.Create(ctx, job.ScanJob{ID: jobID, Status: job.Queued}))
	require.NoError(t, s.Finish(ctx, jobID, json.RawMessage(`{"a":1}`)))

	got, err := s.Get(ctx, jobID)
	require.NoError(t, err)
	got.Report[2] = 'X' // mutate through the returned copy

	again, err := s.Get(ctx, jobID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(again.Report), "the stored report must be unaffected")
}
