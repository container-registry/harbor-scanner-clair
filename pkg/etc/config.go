// Package etc holds the adapter configuration. Everything is environment, with
// the SCANNER_ prefix, parsed once at startup and then validated so an unusable
// deployment fails loudly instead of silently.
package etc

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/jackc/pgx/v5"
)

// Recognized values for SCANNER_STORE_BACKEND, in their canonical (normalized)
// form. Anything else is rejected at startup rather than silently taking the
// Postgres path.
const (
	StoreBackendPostgres = "postgres"
	StoreBackendMemory   = "memory"
)

// The job budget. These are constants for now; the Clair timeouts they will be
// derived from do not exist yet.
const (
	// indexBudget is how long the artifact may spend being indexed.
	indexBudget = 10 * time.Minute
	// reportBudget is how long the report may be waited for after indexing.
	reportBudget = 5 * time.Minute
	// jobOverhead covers the manifest fetch and the terminal store writes.
	jobOverhead = 30 * time.Second
	// lockOverhead keeps the row lock alive past the job it guards.
	lockOverhead = 30 * time.Second
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API      APIConfig
	TLS      TLSConfig
	Clair    ClairConfig
	Store    Store
	Postgres Postgres
	JobQueue JobQueue
}

type APIConfig struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ClientCAs      []string      `env:"SCANNER_API_SERVER_CLIENT_CAS"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	MetricsEnabled bool          `env:"SCANNER_API_SERVER_METRICS_ENABLED" envDefault:"true"`
	// APIKey arms the X-ScannerAdapter-API-Key check on /api/v1. Empty means the
	// middleware is not mounted at all; the probes and /metrics are never behind
	// it, because an orchestrator and a Prometheus scrape cannot send it.
	APIKey string `env:"SCANNER_API_AUTH_API_KEY"`
}

func (c *APIConfig) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

// TLSConfig is the outbound trust configuration, despite the CLIENTCAS name:
// the listed PEM bundles are appended to the system pool used when dialing
// Clair and the registry.
type TLSConfig struct {
	ClientCAs          []string `env:"SCANNER_TLS_CLIENTCAS"`
	InsecureSkipVerify bool     `env:"SCANNER_TLS_INSECURE_SKIP_VERIFY" envDefault:"false"`

	RootCAs *x509.CertPool
}

type ClairConfig struct {
	URL string `env:"SCANNER_CLAIR_URL" envDefault:"http://harbor-harbor-clair:6060"`
}

type Store struct {
	// Backend selects the persistence backend: "postgres" (production default)
	// or "memory" (dev and tests only).
	Backend string `env:"SCANNER_STORE_BACKEND" envDefault:"postgres"`
	// ScanJobTTL must exceed the worst-case queue wait plus the worst-case scan
	// duration. Harbor's report polling has no total timeout: it builds a fresh
	// timer on every iteration of its poll loop and throws it away on the next
	// 302, so the only thing that ends a queued job is this TTL. When the record
	// expires the adapter 404s and Harbor gives up. Raising worker concurrency
	// shortens the wait; adding replicas is the supported way to do that,
	// because memory is per worker.
	ScanJobTTL time.Duration `env:"SCANNER_STORE_SCAN_JOB_TTL" envDefault:"1h"`
}

// Postgres is the connection to the database holding the scan_job table. It has
// no default: the adapter cannot guess a DSN, and a wrong guess would fail at
// the first scan instead of at startup.
type Postgres struct {
	URL      string `env:"SCANNER_STORE_POSTGRES_URL"`
	MaxConns int32  `env:"SCANNER_STORE_POSTGRES_MAX_CONNS" envDefault:"5"`
}

type JobQueue struct {
	WorkerConcurrency int `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
}

// JobDeadline is the longest a single job may legitimately take.
func (c Config) JobDeadline() time.Duration {
	return indexBudget + reportBudget + jobOverhead
}

// LockTTL is how long a claimed scan_job row stays locked. The lock must
// outlive the job it guards, so it is the job deadline plus a backstop: the
// per-job deadline always fires first, and a worker never outlives its claim.
func (c Config) LockTTL() time.Duration {
	return c.JobDeadline() + lockOverhead
}

// LogLevel maps SCANNER_LOG_LEVEL onto a slog level. "trace" is accepted for
// continuity with the logrus levels this replaced and means Debug.
func LogLevel() slog.Level {
	value, ok := os.LookupEnv("SCANNER_LOG_LEVEL")
	if !ok {
		return slog.LevelInfo
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error", "fatal", "panic":
		return slog.LevelError
	case "warn", "warning":
		return slog.LevelWarn
	case "trace", "debug":
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

func GetConfig() (Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, err
	}

	var err error
	cfg.TLS.RootCAs, err = x509.SystemCertPool()
	if err != nil {
		slog.Warn("Error while loading system root CAs", slog.String("err", err.Error()))
	}
	if cfg.TLS.RootCAs == nil {
		slog.Debug("Creating empty root CAs pool")
		cfg.TLS.RootCAs = x509.NewCertPool()
	}

	for _, certFile := range cfg.TLS.ClientCAs {
		certs, readErr := os.ReadFile(strings.TrimSpace(certFile))
		if readErr != nil {
			return cfg, fmt.Errorf("failed to append %q to root CAs pool: %w", certFile, readErr)
		}
		if ok := cfg.TLS.RootCAs.AppendCertsFromPEM(certs); !ok {
			return cfg, fmt.Errorf("file %q contains no usable certificate", certFile)
		}
		slog.Debug("Client CA appended to root CAs pool", slog.String("cert", certFile))
	}

	cfg.Store.Backend = strings.ToLower(strings.TrimSpace(cfg.Store.Backend))
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// validate rejects settings that would otherwise fail silently and late rather
// than loudly at startup:
//
//   - an unknown store backend would take the Postgres code path while skipping
//     the connectivity check;
//   - a missing or unparseable DSN turns into a connection error on the first
//     scan instead of a startup failure;
//   - a non-positive ScanJobTTL creates records that are already expired, so
//     every accepted scan 404s on the first poll.
func (c Config) validate() error {
	// SCANNER_CLAIR_DATABASE_URL is gone with the direct Postgres read it
	// existed for. Rejecting it explicitly beats ignoring a variable an operator
	// deliberately set and then wondering why the vulnerability database
	// timestamp never appears.
	if _, ok := os.LookupEnv("SCANNER_CLAIR_DATABASE_URL"); ok {
		return fmt.Errorf("SCANNER_CLAIR_DATABASE_URL is no longer supported: " +
			"the adapter no longer connects to Clair's database, so the variable has no effect and must be removed")
	}
	// The Redis store is gone. An operator upgrading from 1.x who leaves these
	// set would otherwise get an adapter that ignores them, connects nowhere and
	// fails on the first scan with a message pointing at the wrong subsystem.
	for removed, replacement := range map[string]string{
		"SCANNER_STORE_REDIS_URL":          "SCANNER_STORE_POSTGRES_URL",
		"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "SCANNER_STORE_SCAN_JOB_TTL",
	} {
		if _, ok := os.LookupEnv(removed); ok {
			return fmt.Errorf("%s is no longer supported: the job store is Postgres, use %s instead",
				removed, replacement)
		}
	}
	// Partial TLS is a typo in one of two secrets, and IsTLSEnabled requires
	// both, so the old behavior was to silently serve plaintext -- the failure
	// mode a deployment can least afford to have go unnoticed.
	if (c.API.TLSCertificate == "") != (c.API.TLSKey == "") {
		return fmt.Errorf("SCANNER_API_SERVER_TLS_CERTIFICATE and SCANNER_API_SERVER_TLS_KEY must be set together " +
			"(only one is set; the server would silently start without TLS)")
	}
	if len(c.API.ClientCAs) > 0 && !c.API.IsTLSEnabled() {
		return fmt.Errorf("SCANNER_API_SERVER_CLIENT_CAS requires TLS " +
			"(SCANNER_API_SERVER_TLS_CERTIFICATE and SCANNER_API_SERVER_TLS_KEY); client certificates are never verified without it)")
	}
	// A non-positive server timeout means "no timeout" to net/http, so a typo
	// silently removes the slow-client protection instead of tightening it.
	for name, d := range map[string]time.Duration{
		"SCANNER_API_SERVER_READ_TIMEOUT":  c.API.ReadTimeout,
		"SCANNER_API_SERVER_WRITE_TIMEOUT": c.API.WriteTimeout,
		"SCANNER_API_SERVER_IDLE_TIMEOUT":  c.API.IdleTimeout,
	} {
		if d <= 0 {
			return fmt.Errorf("%s must be positive, got %s", name, d)
		}
	}
	if strings.TrimSpace(c.Clair.URL) == "" {
		return fmt.Errorf("SCANNER_CLAIR_URL must not be empty")
	}
	switch c.Store.Backend {
	case StoreBackendPostgres, StoreBackendMemory:
	default:
		return fmt.Errorf("SCANNER_STORE_BACKEND must be %q or %q, got %q",
			StoreBackendPostgres, StoreBackendMemory, c.Store.Backend)
	}
	// Checked before the memory-backend return: the in-process queue starts
	// exactly WorkerConcurrency consumers, so a value of 0 there produces an
	// adapter that accepts scans and has nobody to run them.
	if c.JobQueue.WorkerConcurrency < 1 {
		return fmt.Errorf("SCANNER_JOB_QUEUE_WORKER_CONCURRENCY must be at least 1, got %d", c.JobQueue.WorkerConcurrency)
	}
	if c.Store.Backend == StoreBackendMemory {
		return nil
	}
	if strings.TrimSpace(c.Postgres.URL) == "" {
		return fmt.Errorf("SCANNER_STORE_POSTGRES_URL must be set when SCANNER_STORE_BACKEND is %q", StoreBackendPostgres)
	}
	// Parsed here rather than at pool construction so a typo in the DSN is
	// reported with the variable that carries it.
	if _, err := pgx.ParseConfig(c.Postgres.URL); err != nil {
		return fmt.Errorf("SCANNER_STORE_POSTGRES_URL is not a valid connection string: %w", err)
	}
	if c.Postgres.MaxConns < 1 {
		return fmt.Errorf("SCANNER_STORE_POSTGRES_MAX_CONNS must be at least 1, got %d", c.Postgres.MaxConns)
	}
	if c.Store.ScanJobTTL <= 0 {
		return fmt.Errorf("SCANNER_STORE_SCAN_JOB_TTL must be positive, got %s", c.Store.ScanJobTTL)
	}
	return nil
}
