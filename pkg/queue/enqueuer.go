// Package queue accepts scan jobs and runs them.
//
// The Postgres backend has no transport of its own: the scan_job row the
// enqueuer writes is the queue entry, and a worker takes it with a single
// locking UPDATE (see pkg/persistence/postgres). One write means there is no
// window in which a record and a queue entry can disagree, and a job outlives
// the process that accepted it -- the in-process pool this replaces lost every
// queued and running scan on restart.
//
// The memory backend keeps an in-process channel for local development, where
// there is no database to hold either the records or the queue.
package queue

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
)

// undispatchedWriteTimeout bounds the cleanup write for a job that could not be
// queued. It runs detached from the request context, so it needs its own bound.
const undispatchedWriteTimeout = 5 * time.Second

// stopTimeout bounds Stop(). A worker in the middle of a scan does not return to
// its loop until the job finishes, which can take the full job deadline. The
// signal handler calls Stop() directly, so waiting for that unconditionally
// would stall SIGTERM until the orchestrator escalates to SIGKILL. Past this
// deadline Stop() returns and lets the process exit; the abandoned job keeps its
// row lock until it expires and is then claimed by another worker, which is a
// better outcome than the SIGKILL it would otherwise wait for.
const stopTimeout = 10 * time.Second

// Deadlines bounds one job. JobDeadline must be the shorter of the two: the scan
// is cut off while its row is still locked, so a worker can never outlive the
// lock that keeps a second worker off the same job.
type Deadlines struct {
	LockTTL     time.Duration
	JobDeadline time.Duration
}

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type Worker interface {
	Start(ctx context.Context)
	Stop()
	// Depth reports how many jobs are waiting to be picked up. It backs the
	// queue_depth gauge and runs on the Prometheus scrape goroutine, so
	// implementations must respect the caller's context deadline.
	Depth(ctx context.Context) (int64, error)
}

// Job is the in-process queue payload. The Postgres backend has none: the
// scan_job row carries the request, and the worker reads it back on claim.
type Job struct {
	ID      string
	Request harbor.ScanRequest
	// EnqueuedAt travels with the payload so the worker can report how long the
	// job waited. Queue wait is what distinguishes "scans are slow" from "the
	// worker pool is too small for the rate Harbor dispatches at".
	EnqueuedAt time.Time
}

type enqueuer struct {
	store persistence.Store
	// dispatch hands the accepted job to an in-process transport. The Postgres
	// backend leaves it nil: the record Create just wrote is already the queue
	// entry, so there is no second write to make and no failure between them.
	dispatch func(ctx context.Context, j Job) error
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	jobID, err := makeIdentifier()
	if err != nil {
		return "", err
	}
	logger := slog.With(slog.String("scan_job_id", jobID))
	logger.Debug("Enqueueing scan job")

	if err = e.store.Create(ctx, job.ScanJob{ID: jobID, Status: job.Queued, Request: request}); err != nil {
		metrics.EnqueueFailuresTotal.Inc()
		return "", fmt.Errorf("enqueuing scan job: %w", err)
	}

	if e.dispatch != nil {
		if err = e.dispatch(ctx, Job{ID: jobID, Request: request, EnqueuedAt: time.Now().UTC()}); err != nil {
			metrics.EnqueueFailuresTotal.Inc()
			e.markUndispatched(ctx, logger, jobID, err)
			return "", fmt.Errorf("enqueuing scan job: %w", err)
		}
	}

	metrics.EnqueuedTotal.Inc()
	logger.Debug("Successfully enqueued scan job")
	return jobID, nil
}

// markUndispatched records a job whose store record exists but whose dispatch
// failed. Left Queued it is indistinguishable from a job merely waiting for a
// worker, so Harbor would poll it until the TTL rather than being told why.
//
// The write is FailIfQueued rather than an unconditional UpdateStatus: a
// dispatch error does not prove non-delivery, so a worker may already be running
// -- or have finished -- the job, and only a record still sitting in Queued may
// be claimed as failed.
//
// It runs on a context detached from the caller's. The common reason dispatch
// failed is that ctx is already done, and reusing it would make the cleanup fail
// for exactly the same reason -- the same trap that stranded terminal writes in
// scan.controller.
func (e *enqueuer) markUndispatched(ctx context.Context, logger *slog.Logger, scanJobID string, cause error) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), undispatchedWriteTimeout)
	defer cancel()

	msg := fmt.Sprintf("scan job could not be queued: %v (if the queue write did land, a worker may still run it)", cause)
	if uErr := e.store.FailIfQueued(writeCtx, scanJobID, msg); uErr != nil {
		logger.Warn("Could not mark an undispatched scan job as failed",
			slog.String("err", uErr.Error()))
	}
}

// observeQueueWait skips the zero value: a job whose enqueue time is unknown
// would report a wait measured from the epoch and wreck the histogram.
func observeQueueWait(enqueuedAt time.Time) {
	if enqueuedAt.IsZero() {
		return
	}
	metrics.QueueWaitSeconds.Observe(time.Since(enqueuedAt).Seconds())
}

// makeIdentifier fails rather than returning an empty ID: every job would then
// collide on the same store key, which is near-undiagnosable in production.
func makeIdentifier() (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating scan job identifier: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
