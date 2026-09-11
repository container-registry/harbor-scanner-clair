// Package etc holds the adapter configuration. Everything is environment, with
// the SCANNER_ prefix, parsed once at startup and then validated so an unusable
// deployment fails loudly instead of silently.
package etc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/jackc/pgx/v5"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
)

// Recognized values for SCANNER_STORE_BACKEND, in their canonical (normalized)
// form. Anything else is rejected at startup rather than silently taking the
// Postgres path.
const (
	StoreBackendPostgres = "postgres"
	StoreBackendMemory   = "memory"
)

// The job budget on top of the two configurable Clair timeouts.
const (
	// jobOverhead covers the manifest fetch and the terminal store writes.
	jobOverhead = 30 * time.Second
	// lockOverhead keeps the row lock alive past the job it guards.
	lockOverhead = 30 * time.Second
	// ttlOverhead is the slack on the derived scan job TTL, following the same
	// 2*budget+3s rule the trivy adapter applies to its scan timeout.
	ttlOverhead = 3 * time.Second
)

// scanJobTTLEnv is looked up directly, because an unset TTL is derived from the
// job budget and env.Parse cannot distinguish unset from explicitly zero.
const scanJobTTLEnv = "SCANNER_STORE_SCAN_JOB_TTL"

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
	// URL is Clair's API root. The default matches clairctl's; the 1.x default
	// pointed at Harbor's bundled Clair, which no longer ships.
	URL string `env:"SCANNER_CLAIR_URL" envDefault:"http://clair:6060"`
	// PSK is the pre-shared key, base64 exactly as it appears in Clair's
	// auth.psk.key. Empty means Clair runs unauthenticated.
	PSK string `env:"SCANNER_CLAIR_PSK"`
	// JWTIssuer must appear in Clair's auth.psk.iss list, or every request is
	// rejected with a 401.
	JWTIssuer string `env:"SCANNER_CLAIR_JWT_ISSUER" envDefault:"harbor-scanner-clair"`
	// IndexTimeout bounds the synchronous index call, every layer fetch
	// included. It has to stay under Harbor's registry token expiration
	// (token_expiration, 30m by default): the token is minted when the scan is
	// requested and Clair pulls the blobs with it.
	IndexTimeout time.Duration `env:"SCANNER_CLAIR_INDEX_TIMEOUT" envDefault:"10m"`
	// RequestTimeout bounds every other Clair call and the manifest GET.
	RequestTimeout time.Duration `env:"SCANNER_CLAIR_REQUEST_TIMEOUT" envDefault:"30s"`
	// ReportRetryTimeout is the budget for the whole report retry loop, which
	// waits out a matcher that is still loading its first vulnerability data.
	ReportRetryTimeout time.Duration `env:"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT" envDefault:"5m"`
}

// IsPSKEnabled reports whether the adapter authenticates to Clair. Reported in
// the scanner metadata; the key itself never is.
func (c ClairConfig) IsPSKEnabled() bool {
	return c.PSK != ""
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
	//
	// Unset, it is derived from the job budget.
	ScanJobTTL time.Duration `env:"SCANNER_STORE_SCAN_JOB_TTL"`
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

// JobDeadline is the longest a single job may legitimately take: the index
// call, the report retry loop, and the overhead around both.
func (c Config) JobDeadline() time.Duration {
	return c.Clair.IndexTimeout + c.Clair.ReportRetryTimeout + jobOverhead
}

// LockTTL is how long a claimed scan_job row stays locked. The lock must
// outlive the job it guards, so it is the job deadline plus a backstop: the
// per-job deadline always fires first, and a worker never outlives its claim.
func (c Config) LockTTL() time.Duration {
	return c.JobDeadline() + lockOverhead
}

// deriveScanJobTTL is the default store TTL: two whole job budgets plus slack,
// so a job that waits one full budget in the queue and then runs for another
// still has a record to write its result to.
func deriveScanJobTTL(lockTTL time.Duration) time.Duration {
	return 2*lockTTL + ttlOverhead
}

// ClairClientConfig is the Clair connection as pkg/clair wants it, so the
// environment names live in exactly one place.
func (c Config) ClairClientConfig() clair.Config {
	return clair.Config{
		URL:                c.Clair.URL,
		PSK:                c.Clair.PSK,
		Issuer:             c.Clair.JWTIssuer,
		IndexTimeout:       c.Clair.IndexTimeout,
		RequestTimeout:     c.Clair.RequestTimeout,
		ReportRetryTimeout: c.Clair.ReportRetryTimeout,
	}
}

// Outbound is the TLS configuration for everything the adapter dials: Clair and
// the registry. RootCAs is the system pool plus SCANNER_TLS_CLIENTCAS.
func (c TLSConfig) Outbound() *tls.Config {
	return &tls.Config{
		RootCAs:            c.RootCAs,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // opt-in via SCANNER_TLS_INSECURE_SKIP_VERIFY
		MinVersion:         tls.VersionTLS12,
	}
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
	if _, set := os.LookupEnv(scanJobTTLEnv); !set {
		cfg.Store.ScanJobTTL = deriveScanJobTTL(cfg.LockTTL())
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	if cfg.Store.ScanJobTTL < cfg.JobDeadline() {
		// Not rejected: an operator may cap the TTL deliberately. But a job that
		// runs to its deadline then finds its record expired and is lost.
		slog.Warn("Scan job TTL is shorter than the job deadline; a slow but successful scan can expire before its report is stored",
			slog.String("env", scanJobTTLEnv), slog.Duration("ttl", cfg.Store.ScanJobTTL),
			slog.Duration("job_deadline", cfg.JobDeadline()))
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
			"the adapter reads the vulnerability database timestamp from Clair's HTTP API, " +
			"so the variable has no effect and must be removed")
	}
	// The Redis store is gone. An operator upgrading from 1.x who leaves these
	// set would otherwise get an adapter that ignores them, connects nowhere and
	// fails on the first scan with a message pointing at the wrong subsystem.
	for removed, replacement := range map[string]string{
		"SCANNER_STORE_REDIS_URL":          "SCANNER_STORE_POSTGRES_URL",
		"SCANNER_STORE_REDIS_SCAN_JOB_TTL": scanJobTTLEnv,
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
	if err := validateClairURL(c.Clair.URL); err != nil {
		return err
	}
	// A PSK that is not base64 reaches Clair as a wrong key and comes back as a
	// 401 on every scan, which reads like a permissions problem rather than a
	// typo in a secret.
	if c.Clair.PSK != "" {
		if _, err := base64.StdEncoding.DecodeString(c.Clair.PSK); err != nil {
			return fmt.Errorf("SCANNER_CLAIR_PSK must be standard base64, exactly as it appears in Clair's auth.psk.key: %w", err)
		}
	}
	// A non-positive Clair timeout means "no deadline" once it reaches
	// context.WithTimeout, so a wedged index call would hold a worker until the
	// job lock expires instead of failing inside its budget.
	for name, d := range map[string]time.Duration{
		"SCANNER_CLAIR_INDEX_TIMEOUT":        c.Clair.IndexTimeout,
		"SCANNER_CLAIR_REQUEST_TIMEOUT":      c.Clair.RequestTimeout,
		"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT": c.Clair.ReportRetryTimeout,
	} {
		if d <= 0 {
			return fmt.Errorf("%s must be positive, got %s", name, d)
		}
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
		return fmt.Errorf("%s must be positive, got %s", scanJobTTLEnv, c.Store.ScanJobTTL)
	}
	return nil
}

// validateClairURL rejects a value the Clair client would only fail on at the
// first scan. env.Parse takes any string, and a hostname without a scheme
// produces requests to a relative URL that never leave the process.
func validateClairURL(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("SCANNER_CLAIR_URL must not be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("SCANNER_CLAIR_URL is not a valid URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("SCANNER_CLAIR_URL must be an absolute http(s) URL, got %q", value)
	}
	return nil
}
