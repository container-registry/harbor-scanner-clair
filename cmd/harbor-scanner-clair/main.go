// Command harbor-scanner-clair is the Harbor Pluggable Scanner Adapter for
// Clair. It serves the Scanner Adapter API v1: Harbor posts a scan request, the
// adapter hands the artifact's layers to Clair and returns the vulnerability
// report Harbor polls for.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/http/api"
	v1 "github.com/container-registry/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/postgres"
	"github.com/container-registry/harbor-scanner-clair/pkg/queue"
	"github.com/container-registry/harbor-scanner-clair/pkg/registry"
	"github.com/container-registry/harbor-scanner-clair/pkg/scan"
)

// Stamped at build time by the Taskfile ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// queueDepthTimeout bounds the count behind the queue_depth gauge. It runs on
// the Prometheus scrape goroutine, so it must not outlive a scrape.
const queueDepthTimeout = 2 * time.Second

// readyPingTimeout bounds the database ping behind /probe/ready, so a wedged
// Postgres answers 503 instead of holding the probe open.
const readyPingTimeout = 2 * time.Second

// startupTimeout bounds the first connection and the schema statement. Without
// it an unreachable database leaves the process hanging before it ever binds a
// port, so the readiness probe cannot report anything either.
const startupTimeout = 30 * time.Second

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("harbor-scanner-clair %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: etc.LogLevel()})))

	info := etc.BuildInfo{Version: version, Commit: commit, Date: date}
	if err := run(context.Background(), info); err != nil {
		slog.Error("fatal", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, info etc.BuildInfo) error {
	slog.Info("Starting harbor-scanner-clair",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("built_at", info.Date),
		slog.Int("uid", os.Getuid()),
	)

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	// The error used to be swallowed by a format string that printed the nil
	// client instead of the cause, so a misconfigured Clair endpoint failed
	// with an unreadable message.
	clairClient, err := clair.NewClient(config.TLS, config.Clair)
	if err != nil {
		return fmt.Errorf("constructing clair client: %w", err)
	}

	var (
		store   persistence.Store
		pgStore *postgres.Store
		pool    *pgxpool.Pool
	)
	// etc.GetConfig has already normalized and validated Store.Backend, so this
	// comparison and the readiness probe agree on the same value.
	usePostgres := config.Store.Backend == etc.StoreBackendPostgres
	if usePostgres {
		if pool, err = newPool(ctx, config.Postgres); err != nil {
			return err
		}
		defer pool.Close()

		// The schema is applied at startup, so a database that is unreachable
		// now fails the process instead of failing every scan later.
		schemaCtx, cancel := context.WithTimeout(ctx, startupTimeout)
		pgStore, err = postgres.New(schemaCtx, pool, postgres.Config{ScanJobTTL: config.Store.ScanJobTTL})
		cancel()
		if err != nil {
			return err
		}
		store = pgStore
	} else {
		store = memory.NewStore()
	}

	scanner := harbor.ClairScanner()
	controller := scan.NewController(
		store,
		clairClient,
		registry.NewClientFactory(config.TLS).Get(),
		scanner,
	)

	// The enqueuer and the worker are always built as a pair. A conditional
	// worker with an unconditional enqueuer produces an adapter that starts,
	// reports healthy, and has no consumer at all -- and whose enqueuer
	// dereferences a nil store on the first scan.
	var (
		enqueuer queue.Enqueuer
		worker   queue.Worker
	)
	deadlines := queue.Deadlines{LockTTL: config.LockTTL(), JobDeadline: config.JobDeadline()}
	if usePostgres {
		enqueuer, worker = queue.NewPostgresQueue(config.JobQueue, deadlines, pgStore, controller)
	} else {
		slog.Warn("Store backend is memory: scan jobs and reports are held in this process only. " +
			"Nothing survives a restart and a second replica shares no state. Use SCANNER_STORE_BACKEND=postgres in production.")
		enqueuer, worker = queue.NewInProcessQueue(config.JobQueue, deadlines, store, controller)
	}

	metrics.MustRegisterQueueDepth(func() float64 {
		dctx, dcancel := context.WithTimeout(ctx, queueDepthTimeout)
		defer dcancel()
		n, derr := worker.Depth(dctx)
		if derr != nil {
			// NaN, not 0: an unreadable queue must not render as an empty one.
			return math.NaN()
		}
		return float64(n)
	})

	ready := func(rctx context.Context) error {
		if pgStore == nil {
			return nil
		}
		pingCtx, cancel := context.WithTimeout(rctx, readyPingTimeout)
		defer cancel()
		return pgStore.Ping(pingCtx)
	}

	// The vulnerability-database timestamp is injected rather than read from the
	// Clair client inside the handler, so a Clair that cannot answer costs the
	// metadata endpoint one property instead of a failed request.
	vulnDBUpdatedAt := func(context.Context) (time.Time, bool) {
		updatedAt, uErr := clairClient.GetVulnerabilityDatabaseUpdatedAt()
		if uErr != nil {
			slog.Warn("Failed to get vulnerability database updated time", slog.String("err", uErr.Error()))
			return time.Time{}, false
		}
		if updatedAt == nil {
			return time.Time{}, false
		}
		return *updatedAt, true
	}

	apiHandler := v1.NewAPIHandler(info, config, scanner, enqueuer, store, ready, vulnDBUpdatedAt)
	apiServer, err := api.NewServer(config.API, apiHandler)
	if err != nil {
		return fmt.Errorf("constructing api server: %w", err)
	}

	worker.Start(ctx)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		slog.Info("Trapped os signal", slog.String("signal", captured.String()))

		apiServer.Shutdown()
		worker.Stop()
		close(shutdownComplete)
	}()

	// A non-nil serve error is fatal (bind failure, bad TLS material) and must
	// propagate out of run; a nil one means Shutdown closed the listener, so the
	// only thing left is to wait for the signal handler to finish cleanup.
	if err := <-apiServer.ListenAndServe(); err != nil {
		return fmt.Errorf("api server: %w", err)
	}
	<-shutdownComplete
	return nil
}

// newPool dials Postgres and proves the credentials before anything else runs.
// pgxpool connects lazily, so without the ping a bad DSN or a firewalled
// database would only surface on the first scan.
func newPool(ctx context.Context, config etc.Postgres) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(config.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing SCANNER_STORE_POSTGRES_URL: %w", err)
	}
	poolConfig.MaxConns = config.MaxConns

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("constructing the postgres pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err = pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	return pool, nil
}
