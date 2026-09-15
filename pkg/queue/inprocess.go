package queue

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/scan"
)

// inProcessBacklog caps the channel between the HTTP handler and the workers.
// Past it Enqueue fails rather than blocking the handler past Harbor's 5s client
// timeout: a 500 that Harbor records against the scan beats a request that hangs
// and a job Harbor believes was accepted.
const inProcessBacklog = 64

// NewInProcessQueue builds the enqueuer/worker pair for SCANNER_STORE_BACKEND=memory,
// where there is no database to hold either the queue or the job records.
//
// It exists because the alternative is worse: the Postgres enqueuer would
// dereference a store that is nil under the memory backend, so POST
// /api/v1/scan would panic mid-request. An adapter that starts, reports healthy,
// and cannot run a single scan is the failure mode this replaces.
//
// This is a single-process, non-durable mode for local development: nothing
// survives a restart, and two replicas share no state, so Harbor's report poll
// must reach the same process that ran the scan. Production wants Postgres.
func NewInProcessQueue(
	config etc.JobQueue,
	deadlines Deadlines,
	store persistence.Store,
	controller scan.Controller,
) (Enqueuer, Worker) {
	jobs := make(chan Job, inProcessBacklog)

	enq := &enqueuer{
		store: store,
		dispatch: func(ctx context.Context, j Job) error {
			select {
			case jobs <- j:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("in-process job queue is full (%d pending); "+
					"use SCANNER_STORE_BACKEND=postgres for anything beyond local development", inProcessBacklog)
			}
		},
	}

	return enq, &inProcessWorker{
		concurrency: config.WorkerConcurrency,
		deadlines:   deadlines,
		jobs:        jobs,
		controller:  controller,
	}
}

type inProcessWorker struct {
	concurrency int
	deadlines   Deadlines
	jobs        chan Job
	controller  scan.Controller

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     sync.WaitGroup
}

func (w *inProcessWorker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	for range w.concurrency {
		w.done.Add(1)
		go func() {
			defer w.done.Done()
			w.consume(ctx)
		}()
	}
}

// Stop mirrors the Postgres worker: cancel in-flight scans, then bound the drain
// so SIGTERM is not held for the full job deadline by a scan in progress.
func (w *inProcessWorker) Stop() {
	slog.Debug("In-process job queue shutdown started")
	w.stopOnce.Do(func() {
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
		slog.Debug("In-process job queue shutdown completed")
	case <-time.After(stopTimeout):
		slog.Warn("In-process job queue shutdown timed out; abandoning in-flight scans",
			slog.Duration("timeout", stopTimeout))
	}
}

func (w *inProcessWorker) Depth(_ context.Context) (int64, error) {
	return int64(len(w.jobs)), nil
}

func (w *inProcessWorker) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-w.jobs:
			w.runJob(ctx, j)
		}
	}
}

// runJob deliberately omits the row lock the Postgres worker relies on: a
// channel delivers each job to exactly one goroutine, and there is no second
// replica to race with.
func (w *inProcessWorker) runJob(ctx context.Context, j Job) {
	slog.Debug("Executing enqueued scan job", slog.String("scan_job_id", j.ID))
	observeQueueWait(j.EnqueuedAt)
	jobCtx, cancel := context.WithTimeout(ctx, w.deadlines.JobDeadline)
	defer cancel()
	if err := w.controller.Scan(jobCtx, j.ID, j.Request); err != nil {
		slog.Error("Failed to scan artifact", slog.String("err", err.Error()))
	}
}
