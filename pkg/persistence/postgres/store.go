// Package postgres is the production scan-job store. One table holds both the
// records Harbor polls and the queue the workers claim from: Clair already
// requires Postgres, so the adapter needs no second datastore, and a job that
// exists is by definition queued. Terminal writes are conditional on the status
// they expect to find, which closes the overwrite races a read-modify-write
// store cannot.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
)

// The status column is job.ScanJobStatus stored as a smallint. The statements
// below spell the values as SQL literals (an index predicate cannot carry a
// parameter), so these constants exist to tie the two together: a reordered
// iota in pkg/job would otherwise silently change what a row means.
// TestStatusLiteralsMatchTheJobIota pins the mapping.
const (
	statusQueued   = int16(job.Queued)
	statusPending  = int16(job.Pending)
	statusFinished = int16(job.Finished)
	statusFailed   = int16(job.Failed)
)

// ddl is idempotent and runs at every startup: the adapter owns this table, and
// a separate migration step for one table is a deployment failure mode (a
// forgotten job, an ordering constraint against the adapter rollout) with no
// upside.
//
// The claim index is partial on the two non-terminal states, so it stays small
// while finished reports are still being polled -- those rows are the bulk of
// the table and the claim query never looks at them.
const ddl = `
CREATE TABLE IF NOT EXISTS scan_job (
  id           text PRIMARY KEY,
  status       smallint NOT NULL,
  request      jsonb NOT NULL,
  report       bytea,
  error        text NOT NULL DEFAULT '',
  attempts     smallint NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_job_claim ON scan_job (created_at) WHERE status IN (0, 1);
CREATE INDEX IF NOT EXISTS scan_job_expiry ON scan_job (expires_at);
`

// Statements are named rather than inlined so the conditional WHERE clauses --
// the whole point of this store -- are readable side by side.
const (
	// createStmt keeps the SetNX semantics the previous store had: a repeated
	// scan job id must not reset a record a worker is already acting on.
	createStmt = `
INSERT INTO scan_job (id, status, request, expires_at)
VALUES ($1, 0, $2, now() + make_interval(secs => $3))
ON CONFLICT (id) DO NOTHING`

	getStmt = `SELECT status, error, report FROM scan_job WHERE id = $1 AND expires_at > now()`

	// updateStatusStmt refuses to touch a record that is already terminal or has
	// expired. That is what stops a late Failed write from overwriting a stored
	// report, and what turns "the record is gone" into ErrJobNotFound instead of
	// a silent no-op.
	// The parameter is cast explicitly in both places it appears: without it
	// Postgres deduces smallint from the assignment and integer from the IN
	// list, and refuses the statement.
	updateStatusStmt = `
UPDATE scan_job
   SET status = $2::smallint,
       error = COALESCE($3, error),
       locked_until = CASE WHEN $2::smallint IN (2, 3) THEN NULL ELSE locked_until END
 WHERE id = $1 AND status IN (0, 1) AND expires_at > now()`

	// finishStmt is one write and no read: every field of the terminal record is
	// known here. It also extends expires_at, so the TTL bounds how long a
	// finished report is kept for Harbor to poll rather than how long the job
	// had to run. A record that expired while the scan ran is not resurrected:
	// Harbor has already been told the job is gone, and a report nobody polls
	// would sit in the table for another full TTL.
	finishStmt = `
UPDATE scan_job
   SET status = 2, report = $2, error = '', locked_until = NULL,
       expires_at = now() + make_interval(secs => $3)
 WHERE id = $1 AND status = 1 AND expires_at > now()`

	// failIfQueuedStmt claims only a record still sitting in Queued, and reports
	// separately whether the record was there at all: enqueue cleanup must be
	// able to tell "a worker got there first" (leave it alone) from "the record
	// is gone" (ErrJobNotFound). The existence count reads the pre-update
	// snapshot, so it is unaffected by the UPDATE in the same statement.
	failIfQueuedStmt = `
WITH claimed AS (
  UPDATE scan_job SET status = 3, error = $2, locked_until = NULL
   WHERE id = $1 AND status = 0 AND expires_at > now()
  RETURNING id
)
SELECT (SELECT count(*) FROM claimed),
       (SELECT count(*) FROM scan_job WHERE id = $1 AND expires_at > now())`

	// claimStmt is the whole queue: it picks the oldest runnable row, marks it
	// Pending and locks it, in one statement. FOR UPDATE SKIP LOCKED is what
	// lets several workers (and several replicas) claim concurrently without
	// handing the same job to two of them and without queueing on each other's
	// row locks. A row whose locked_until has passed is runnable again, which is
	// how a job survives the worker that was running it being killed.
	claimStmt = `
UPDATE scan_job
   SET status = 1, locked_until = now() + make_interval(secs => $1), attempts = attempts + 1
 WHERE id = (
   SELECT id FROM scan_job
    WHERE (status = 0 OR (status = 1 AND locked_until < now()))
      AND expires_at > now()
    ORDER BY created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
 )
RETURNING id, request, attempts, created_at`

	sweepStmt = `DELETE FROM scan_job WHERE expires_at < now()`

	depthStmt = `SELECT count(*) FROM scan_job WHERE status = 0`
)

// Config is what the store needs beyond the connection pool.
type Config struct {
	// ScanJobTTL is how long a record stays readable: long enough to cover the
	// worst-case queue wait plus the scan, and then to hold the finished report
	// for Harbor to collect. Harbor's report polling has no total timeout -- it
	// builds a fresh timer on every iteration of its poll loop and throws it
	// away on the next 302 -- so the only thing that ends a queued job is this.
	ScanJobTTL time.Duration
}

// Store is the Postgres-backed persistence.Store. It also carries the queue
// operations (Claim, Sweep, Depth), which are the same table and belong on the
// same type; the persistence.Store interface stays narrow because the HTTP
// handler has no business claiming jobs.
type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

var _ persistence.Store = (*Store)(nil)

// New applies the schema and returns the store. The DDL is idempotent, so
// several replicas starting at once is fine; it needs a role that may create
// tables in the target database.
func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Store, error) {
	if _, err := pool.Exec(ctx, ddl); err != nil {
		return nil, fmt.Errorf("applying the scan_job schema: %w", err)
	}
	return &Store{pool: pool, cfg: cfg}, nil
}

func (s *Store) Create(ctx context.Context, scanJob job.ScanJob) error {
	request, err := json.Marshal(scanJob.Request)
	if err != nil {
		return fmt.Errorf("marshaling scan request: %w", err)
	}
	slog.Debug("Saving scan job",
		slog.String("scan_job_id", scanJob.ID),
		slog.String("scan_job_status", scanJob.Status.String()),
		slog.Duration("expire", s.cfg.ScanJobTTL),
	)
	if _, err = s.pool.Exec(ctx, createStmt, scanJob.ID, request, s.cfg.ScanJobTTL.Seconds()); err != nil {
		return fmt.Errorf("creating scan job: %w", err)
	}
	return nil
}

// Get returns nil without an error when there is no live record: the API
// handler answers 404 on that, and an expired record is indistinguishable from
// one that never existed as far as Harbor is concerned.
func (s *Store) Get(ctx context.Context, scanJobID string) (*job.ScanJob, error) {
	var (
		status int16
		errMsg string
		stored []byte
	)
	err := s.pool.QueryRow(ctx, getStmt, scanJobID).Scan(&status, &errMsg, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("getting scan job: %w", err)
	}

	report, err := persistence.DecodeReport(stored)
	if err != nil {
		return nil, err
	}
	return &job.ScanJob{
		ID:     scanJobID,
		Status: job.ScanJobStatus(status),
		Error:  errMsg,
		Report: report,
	}, nil
}

func (s *Store) UpdateStatus(ctx context.Context, scanJobID string, newStatus job.ScanJobStatus, errorMsg ...string) error {
	var msg *string
	if len(errorMsg) > 0 {
		msg = &errorMsg[0]
	}
	tag, err := s.pool.Exec(ctx, updateStatusStmt, scanJobID, int16(newStatus), msg)
	if err != nil {
		return fmt.Errorf("updating scan job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("updating scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	return nil
}

func (s *Store) Finish(ctx context.Context, scanJobID string, report json.RawMessage) error {
	stored, err := persistence.EncodeReport(report)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, finishStmt, scanJobID, stored, s.cfg.ScanJobTTL.Seconds())
	if err != nil {
		return fmt.Errorf("finishing scan job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finishing scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	return nil
}

func (s *Store) FailIfQueued(ctx context.Context, scanJobID, errorMsg string) error {
	var claimed, present int64
	if err := s.pool.QueryRow(ctx, failIfQueuedStmt, scanJobID, errorMsg).Scan(&claimed, &present); err != nil {
		return fmt.Errorf("failing queued scan job: %w", err)
	}
	if present == 0 {
		return fmt.Errorf("scan job (%s): %w", scanJobID, persistence.ErrJobNotFound)
	}
	return nil
}

// Claim is one job handed to a worker: everything needed to run the scan, plus
// the attempt count, which is the only evidence that a previous worker died
// holding this row.
type Claim struct {
	ID        string
	Request   harbor.ScanRequest
	Attempts  int
	CreatedAt time.Time
}

// Claim takes the oldest runnable job and locks it for lockTTL. It returns nil
// without an error when the queue is empty, which is the common case on every
// poll.
//
// lockTTL must outlive the scan the caller then runs: the per-job deadline is
// what stops the work, and the lock is what stops a second worker from starting
// the same job while the first is still on it.
func (s *Store) Claim(ctx context.Context, lockTTL time.Duration) (*Claim, error) {
	var (
		claim   Claim
		request []byte
	)
	err := s.pool.QueryRow(ctx, claimStmt, lockTTL.Seconds()).
		Scan(&claim.ID, &request, &claim.Attempts, &claim.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("claiming scan job: %w", err)
	}
	if err = json.Unmarshal(request, &claim.Request); err != nil {
		return nil, fmt.Errorf("unmarshaling scan request of job (%s): %w", claim.ID, err)
	}
	return &claim, nil
}

// Sweep deletes records past their TTL and reports how many went. Nothing reads
// an expired record (every statement above filters on expires_at), so this is
// housekeeping: without it the table would only ever grow.
func (s *Store) Sweep(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, sweepStmt)
	if err != nil {
		return 0, fmt.Errorf("sweeping expired scan jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Depth counts the jobs still waiting for a worker. It backs the queue_depth
// gauge and runs on the Prometheus scrape goroutine, so it respects ctx.
func (s *Store) Depth(ctx context.Context) (int64, error) {
	var depth int64
	if err := s.pool.QueryRow(ctx, depthStmt).Scan(&depth); err != nil {
		return 0, fmt.Errorf("counting queued scan jobs: %w", err)
	}
	return depth, nil
}

// Ping backs /probe/ready.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging postgres: %w", err)
	}
	return nil
}
