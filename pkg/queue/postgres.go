package queue

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/postgres"
	"github.com/container-registry/harbor-scanner-clair/pkg/scan"
)

// pollInterval is how long an idle worker waits before asking for work again.
// There is deliberately no LISTEN/NOTIFY: it costs a dedicated connection per
// replica and a second code path, to save at most one second on a job that
// takes minutes.
const pollInterval = time.Second

// NewPostgresQueue builds the enqueuer/worker pair for SCANNER_STORE_BACKEND=postgres.
//
// They are always built together. A conditional worker with an unconditional
// enqueuer produces an adapter that starts, reports healthy, accepts scans with
// 202 and has no consumer at all.
func NewPostgresQueue(
	config etc.JobQueue,
	deadlines Deadlines,
	store *postgres.Store,
	controller scan.Controller,
) (Enqueuer, Worker) {
	// No dispatch: Create writes the row that IS the queue entry.
	enq := &enqueuer{store: store}

	return enq, &pgWorker{
		concurrency: config.WorkerConcurrency,
		deadlines:   deadlines,
		store:       store,
		controller:  controller,
		stop:        make(chan struct{}),
	}
}

type pgWorker struct {
	concurrency int
	deadlines   Deadlines
	store       *postgres.Store
	controller  scan.Controller

	stopOnce sync.Once
	stop     chan struct{}
	done     sync.WaitGroup
	// cancel aborts the context handed to in-flight scans, so Stop() tears down
	// the outbound Clair and registry calls rather than waiting out their
	// timeouts.
	cancel context.CancelFunc
}

// Start runs `concurrency` claim loops plus one sweeper.
//
// Nothing here recovers orphaned jobs explicitly, because nothing is orphaned:
// a claim is a row lock with an expiry, so a worker killed mid-scan (OOM,
// SIGKILL) leaves a row that becomes claimable again by itself. The in-process
// pool this replaces lost such a scan outright, leaving a record Harbor polled
// until it expired.
func (w *pgWorker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	w.done.Add(1)
	go func() {
		defer w.done.Done()
		w.sweep(ctx)
	}()

	for range w.concurrency {
		w.done.Add(1)
		go func() {
			defer w.done.Done()
			w.consume(ctx)
		}()
	}
}

func (w *pgWorker) Stop() {
	slog.Debug("Job queue shutdown started")
	w.stopOnce.Do(func() {
		close(w.stop)
		if w.cancel != nil {
			w.cancel()
		}
	})

	drained := make(chan struct{})
	go func() {
		w.done.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		slog.Debug("Job queue shutdown completed")
	case <-time.After(stopTimeout):
		slog.Warn("Job queue shutdown timed out; abandoning in-flight scans",
			slog.Duration("timeout", stopTimeout))
	}
}

func (w *pgWorker) Depth(ctx context.Context) (int64, error) {
	return w.store.Depth(ctx)
}

func (w *pgWorker) consume(ctx context.Context) {
	for {
		claim, err := w.store.Claim(ctx, w.deadlines.LockTTL)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// The database is unreachable or the statement failed. Back off for
			// one poll interval rather than spinning on the error.
			slog.Error("Failed to claim a scan job", slog.String("err", err.Error()))
		} else if claim != nil {
			w.runJob(ctx, claim)
			// Straight back to the queue: a backlog must not drain at one job
			// per poll interval.
			continue
		}
		if !w.wait(ctx, pollInterval) {
			return
		}
	}
}

// runJob bounds the whole job (the registry manifest GET plus every Clair call)
// by a deadline. Start receives context.Background() from main, so without this
// the job would be unbounded: a tarpit or half-open registry can trickle bytes
// for as long as it likes, permanently consuming this worker goroutine (default
// concurrency 1 => all scanning halts until process restart).
//
// The deadline is shorter than the row lock, so the scan is cut off while the
// claim still holds. A scan that ends without writing a terminal status leaves
// its row Pending until the lock expires, and the next claim runs it again.
func (w *pgWorker) runJob(ctx context.Context, claim *postgres.Claim) {
	observeQueueWait(claim.CreatedAt)
	logger := slog.With(slog.String("scan_job_id", claim.ID))
	if claim.Attempts > 1 {
		logger.Warn("Retrying a scan job an earlier worker did not finish",
			slog.Int("attempts", claim.Attempts))
	}
	logger.Debug("Executing enqueued scan job")

	jobCtx, cancel := context.WithTimeout(ctx, w.deadlines.JobDeadline)
	defer cancel()
	if err := w.controller.Scan(jobCtx, claim.ID, claim.Request); err != nil {
		logger.Error("Failed to scan artifact", slog.String("err", err.Error()))
	}
}

// sweep deletes expired records on its own goroutine rather than inside each
// claim loop, so the cost does not multiply with worker concurrency. Nothing
// reads an expired record -- every statement in the store filters on expires_at
// -- so this is housekeeping, not correctness.
func (w *pgWorker) sweep(ctx context.Context) {
	for w.wait(ctx, pollInterval) {
		deleted, err := w.store.Sweep(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("Failed to sweep expired scan jobs", slog.String("err", err.Error()))
			continue
		}
		if deleted > 0 {
			slog.Debug("Swept expired scan jobs", slog.Int64("count", deleted))
		}
	}
}

// wait sleeps for d and reports whether the caller should keep going.
func (w *pgWorker) wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-w.stop:
		return false
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
