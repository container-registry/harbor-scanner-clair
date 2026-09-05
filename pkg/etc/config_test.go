package etc

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
)

type Envs map[string]string

// testDSN is the one variable the postgres backend cannot default: every case
// that expects GetConfig to succeed has to carry it.
const testDSN = "postgres://scanner:scanner@localhost:5432/scanner?sslmode=disable"

func TestLogLevel(t *testing.T) {
	testCases := []struct {
		name     string
		envs     Envs
		expected slog.Level
	}{
		{
			name:     "Should return default log level when env is not set",
			expected: slog.LevelInfo,
		},
		{
			name:     "Should return default log level when env has invalid value",
			envs:     Envs{"SCANNER_LOG_LEVEL": "unknown_level"},
			expected: slog.LevelInfo,
		},
		{
			// trace is kept as an accepted spelling: it was a valid logrus level
			// and is still set in deployments upgraded from 1.x.
			name:     "Should map the legacy trace level to debug",
			envs:     Envs{"SCANNER_LOG_LEVEL": "trace"},
			expected: slog.LevelDebug,
		},
		{
			name:     "Should return debug",
			envs:     Envs{"SCANNER_LOG_LEVEL": "DEBUG"},
			expected: slog.LevelDebug,
		},
		{
			name:     "Should return warn",
			envs:     Envs{"SCANNER_LOG_LEVEL": "warning"},
			expected: slog.LevelWarn,
		},
		{
			name:     "Should return error",
			envs:     Envs{"SCANNER_LOG_LEVEL": "error"},
			expected: slog.LevelError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			assert.Equal(t, tc.expected, LogLevel())
		})
	}
}

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedConfig Config
	}{
		{
			name: "Should return default config",
			envs: Envs{"SCANNER_STORE_POSTGRES_URL": testDSN},
			expectedConfig: Config{
				API: APIConfig{
					Addr:           ":8080",
					ReadTimeout:    parseDuration(t, "15s"),
					WriteTimeout:   parseDuration(t, "15s"),
					IdleTimeout:    parseDuration(t, "60s"),
					MetricsEnabled: true,
				},
				Clair: ClairConfig{
					URL:                "http://clair:6060",
					JWTIssuer:          "harbor-scanner-clair",
					IndexTimeout:       parseDuration(t, "10m"),
					RequestTimeout:     parseDuration(t, "30s"),
					ReportRetryTimeout: parseDuration(t, "5m"),
				},
				Store: Store{
					Backend: StoreBackendPostgres,
					// Derived: 2*LockTTL+3s with the default Clair budgets.
					ScanJobTTL: parseDuration(t, "32m3s"),
				},
				Postgres: Postgres{
					URL:      testDSN,
					MaxConns: 5,
				},
				JobQueue: JobQueue{
					WorkerConcurrency: 1,
				},
			},
		},
		{
			name: "Should overwrite default config with envs",
			envs: Envs{
				"SCANNER_API_SERVER_ADDR":            ":7654",
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
				"SCANNER_API_SERVER_READ_TIMEOUT":    "1h17m",
				"SCANNER_API_SERVER_WRITE_TIMEOUT":   "2h5m",
				"SCANNER_API_SERVER_IDLE_TIMEOUT":    "3m15s",
				"SCANNER_API_SERVER_CLIENT_CAS":      "test/data/ca.crt",
				"SCANNER_API_SERVER_METRICS_ENABLED": "false",
				"SCANNER_API_AUTH_API_KEY":           "s3cret",

				"SCANNER_TLS_INSECURE_SKIP_VERIFY": "true",
				"SCANNER_TLS_CLIENTCAS":            "test/data/ca.crt",

				"SCANNER_CLAIR_URL":                  "https://demo.clair:7080",
				"SCANNER_CLAIR_PSK":                  "c2VjcmV0LXBzaw==",
				"SCANNER_CLAIR_JWT_ISSUER":           "custom-issuer",
				"SCANNER_CLAIR_INDEX_TIMEOUT":        "20m",
				"SCANNER_CLAIR_REQUEST_TIMEOUT":      "45s",
				"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT": "7m",

				"SCANNER_STORE_BACKEND":            "POSTGRES",
				"SCANNER_STORE_POSTGRES_URL":       testDSN,
				"SCANNER_STORE_POSTGRES_MAX_CONNS": "12",
				"SCANNER_STORE_SCAN_JOB_TTL":       "90m",

				"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY": "4",
			},
			expectedConfig: Config{
				API: APIConfig{
					Addr:           ":7654",
					TLSCertificate: "/certs/tls.crt",
					TLSKey:         "/certs/tls.key",
					ClientCAs:      []string{"test/data/ca.crt"},
					ReadTimeout:    parseDuration(t, "1h17m"),
					WriteTimeout:   parseDuration(t, "2h5m"),
					IdleTimeout:    parseDuration(t, "3m15s"),
					MetricsEnabled: false,
					APIKey:         "s3cret",
				},
				Clair: ClairConfig{
					URL:                "https://demo.clair:7080",
					PSK:                "c2VjcmV0LXBzaw==",
					JWTIssuer:          "custom-issuer",
					IndexTimeout:       parseDuration(t, "20m"),
					RequestTimeout:     parseDuration(t, "45s"),
					ReportRetryTimeout: parseDuration(t, "7m"),
				},
				Store: Store{
					// Normalized before validation, so "POSTGRES" cannot take the
					// memory code path, or skip its connectivity check.
					Backend:    StoreBackendPostgres,
					ScanJobTTL: parseDuration(t, "90m"),
				},
				Postgres: Postgres{
					URL:      testDSN,
					MaxConns: 12,
				},
				JobQueue: JobQueue{
					WorkerConcurrency: 4,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)

			cfg, err := GetConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig.API, cfg.API)
			assert.Equal(t, tc.expectedConfig.Clair, cfg.Clair)
			assert.Equal(t, tc.expectedConfig.Store, cfg.Store)
			assert.Equal(t, tc.expectedConfig.Postgres, cfg.Postgres)
			assert.Equal(t, tc.expectedConfig.JobQueue, cfg.JobQueue)
		})
	}
}

// TestDatabaseURLIsRejected pins the removal of the direct Postgres read. An
// operator who still sets the variable must be told it does nothing, rather than
// waiting for a vulnerability-database timestamp that will never appear.
func TestDatabaseURLIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_CLAIR_DATABASE_URL": "postgres://clair@localhost/clair"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_CLAIR_DATABASE_URL")
}

func TestUnknownStoreBackendIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_BACKEND": "redis"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_STORE_BACKEND")
}

// TestRemovedRedisVarsAreRejected pins the upgrade path off the Redis store. An
// operator who leaves these set would otherwise get an adapter that silently
// ignores them and fails on the first scan pointing at the wrong subsystem.
func TestRemovedRedisVarsAreRejected(t *testing.T) {
	for name, replacement := range map[string]string{
		"SCANNER_STORE_REDIS_URL":          "SCANNER_STORE_POSTGRES_URL",
		"SCANNER_STORE_REDIS_SCAN_JOB_TTL": "SCANNER_STORE_SCAN_JOB_TTL",
	} {
		t.Run(name, func(t *testing.T) {
			setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN, name: "whatever"})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
			assert.Contains(t, err.Error(), replacement, "the error must name the variable that replaced it")
		})
	}
}

// TestPostgresURLIsRequired: the adapter cannot guess a DSN, and without this
// check the failure would arrive on the first scan rather than at startup.
func TestPostgresURLIsRequired(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_BACKEND": StoreBackendPostgres})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_STORE_POSTGRES_URL")
}

func TestUnparseablePostgresURLIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": "postgres://user:pass@host:not-a-port/scanner"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_STORE_POSTGRES_URL")
}

func TestNonPositivePostgresMaxConnsIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN, "SCANNER_STORE_POSTGRES_MAX_CONNS": "0"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_STORE_POSTGRES_MAX_CONNS")
}

// TestMemoryBackendNeedsNoDSN keeps local development working without a
// database: `task run` sets nothing but the backend.
func TestMemoryBackendNeedsNoDSN(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_BACKEND": StoreBackendMemory})
	cfg, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, StoreBackendMemory, cfg.Store.Backend)
}

// TestWorkerConcurrencyIsValidatedForBothBackends pins a gap the validation
// could easily have: the memory backend returns early, and the in-process queue
// starts exactly WorkerConcurrency consumers. A value of 0 would produce an
// adapter that starts, reports healthy, accepts scans with 202, and has nobody
// to run them.
func TestWorkerConcurrencyIsValidatedForBothBackends(t *testing.T) {
	for _, backend := range []string{StoreBackendMemory, StoreBackendPostgres} {
		t.Run(backend, func(t *testing.T) {
			setenvs(t, Envs{
				"SCANNER_STORE_BACKEND":                backend,
				"SCANNER_STORE_POSTGRES_URL":           testDSN,
				"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY": "0",
			})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SCANNER_JOB_QUEUE_WORKER_CONCURRENCY")
		})
	}
}

// TestPartialTLSIsRejected pins that a typo in one of two TLS secrets fails the
// deployment instead of silently serving plaintext. IsTLSEnabled requires both,
// so setting only one used to disable transport security without a word.
func TestPartialTLSIsRejected(t *testing.T) {
	for _, tc := range []struct{ name, cert, key string }{
		{"cert without key", "/certs/tls.crt", ""},
		{"key without cert", "", "/certs/tls.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, Envs{
				"SCANNER_API_SERVER_TLS_CERTIFICATE": tc.cert,
				"SCANNER_API_SERVER_TLS_KEY":         tc.key,
			})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be set together")
		})
	}
}

// TestClientCAsWithoutTLSAreRejected: inbound client certificates are only ever
// verified on the TLS branch, so a client CA bundle without a server
// certificate is a security control that silently does nothing.
func TestClientCAsWithoutTLSAreRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_API_SERVER_CLIENT_CAS": "test/data/ca.crt"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_API_SERVER_CLIENT_CAS requires TLS")
}

// TestNonPositiveServerTimeoutsAreRejected: net/http reads a zero timeout as
// "no timeout", so a typo silently removes slow-client protection rather than
// tightening it.
func TestNonPositiveServerTimeoutsAreRejected(t *testing.T) {
	for _, name := range []string{
		"SCANNER_API_SERVER_READ_TIMEOUT",
		"SCANNER_API_SERVER_WRITE_TIMEOUT",
		"SCANNER_API_SERVER_IDLE_TIMEOUT",
	} {
		t.Run(name, func(t *testing.T) {
			setenvs(t, Envs{name: "0s"})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
}

// TestNonPositiveScanJobTTLIsRejected: a record created already expired 404s on
// the first poll, so every accepted scan would be lost.
func TestNonPositiveScanJobTTLIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN, "SCANNER_STORE_SCAN_JOB_TTL": "0s"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_STORE_SCAN_JOB_TTL")
}

// TestJobBudget pins the relation the store TTL has to be compared against: the
// lock must outlive the job it guards, and the default TTL must outlive both.
func TestJobBudget(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN})
	cfg, err := GetConfig()
	require.NoError(t, err)

	assert.Equal(t, 15*time.Minute+30*time.Second, cfg.JobDeadline())
	assert.Equal(t, 16*time.Minute, cfg.LockTTL())
	assert.Equal(t, 32*time.Minute+3*time.Second, cfg.Store.ScanJobTTL)
	assert.Less(t, cfg.JobDeadline(), cfg.LockTTL(),
		"the job deadline must fire first, so a worker never outlives its row lock")
	assert.Greater(t, cfg.Store.ScanJobTTL, cfg.LockTTL(),
		"a job whose record expires while it runs can never report a result")
}

// The budget moves with the Clair timeouts it is made of, so raising the index
// timeout must raise the lock and the derived TTL with it.
func TestJobBudgetFollowsTheClairTimeouts(t *testing.T) {
	setenvs(t, Envs{
		"SCANNER_STORE_POSTGRES_URL":         testDSN,
		"SCANNER_CLAIR_INDEX_TIMEOUT":        "20m",
		"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT": "10m",
	})
	cfg, err := GetConfig()
	require.NoError(t, err)

	assert.Equal(t, 30*time.Minute+30*time.Second, cfg.JobDeadline())
	assert.Equal(t, 31*time.Minute, cfg.LockTTL())
	assert.Equal(t, 62*time.Minute+3*time.Second, cfg.Store.ScanJobTTL)
}

// An explicit TTL is kept as given: the derivation only fills in an unset one,
// and an operator who sizes the value for their queue must not be overruled.
func TestExplicitScanJobTTLWins(t *testing.T) {
	setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN, "SCANNER_STORE_SCAN_JOB_TTL": "4h"})
	cfg, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 4*time.Hour, cfg.Store.ScanJobTTL)
}

func TestClairURLIsValidated(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty", "  "},
		{"no scheme", "clair:6060"},
		{"not http", "unix:///var/run/clair.sock"},
		{"no host", "http://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, Envs{"SCANNER_CLAIR_URL": tc.value})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SCANNER_CLAIR_URL")
		})
	}
}

// A PSK that is not base64 reaches Clair as a wrong key and comes back as a 401
// on every scan, which reads like a permissions problem rather than a typo.
func TestInvalidPSKIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_CLAIR_PSK": "not base64!"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_CLAIR_PSK")
}

func TestNonPositiveClairTimeoutsAreRejected(t *testing.T) {
	for _, name := range []string{
		"SCANNER_CLAIR_INDEX_TIMEOUT",
		"SCANNER_CLAIR_REQUEST_TIMEOUT",
		"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT",
	} {
		t.Run(name, func(t *testing.T) {
			setenvs(t, Envs{name: "0s"})
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
}

// The Clair client is configured from exactly these environment names, so the
// mapping is pinned rather than left to a future rename.
func TestClairClientConfig(t *testing.T) {
	setenvs(t, Envs{
		"SCANNER_STORE_POSTGRES_URL":         testDSN,
		"SCANNER_CLAIR_URL":                  "https://clair.example.com",
		"SCANNER_CLAIR_PSK":                  "c2VjcmV0LXBzaw==",
		"SCANNER_CLAIR_JWT_ISSUER":           "custom-issuer",
		"SCANNER_CLAIR_INDEX_TIMEOUT":        "11m",
		"SCANNER_CLAIR_REQUEST_TIMEOUT":      "12s",
		"SCANNER_CLAIR_REPORT_RETRY_TIMEOUT": "13m",
	})
	cfg, err := GetConfig()
	require.NoError(t, err)

	assert.Equal(t, clair.Config{
		URL:                "https://clair.example.com",
		PSK:                "c2VjcmV0LXBzaw==",
		Issuer:             "custom-issuer",
		IndexTimeout:       11 * time.Minute,
		RequestTimeout:     12 * time.Second,
		ReportRetryTimeout: 13 * time.Minute,
	}, cfg.ClairClientConfig())
	assert.True(t, cfg.Clair.IsPSKEnabled())
}

// SCANNER_TLS_CLIENTCAS is the outbound trust bundle despite its name, and the
// pool it produces is what both Clair and the registry are dialed with.
func TestOutboundTLSConfig(t *testing.T) {
	setenvs(t, Envs{
		"SCANNER_STORE_POSTGRES_URL":       testDSN,
		"SCANNER_TLS_CLIENTCAS":            "test/data/ca.crt",
		"SCANNER_TLS_INSECURE_SKIP_VERIFY": "true",
	})
	cfg, err := GetConfig()
	require.NoError(t, err)

	outbound := cfg.TLS.Outbound()
	require.NotNil(t, outbound)
	assert.True(t, outbound.InsecureSkipVerify)
	assert.Equal(t, cfg.TLS.RootCAs, outbound.RootCAs)
	assert.NotNil(t, outbound.RootCAs)
}

// An unreadable or unparseable outbound CA bundle fails the deployment rather
// than silently leaving the pool without it.
func TestUnusableOutboundCABundleIsRejected(t *testing.T) {
	setenvs(t, Envs{"SCANNER_TLS_CLIENTCAS": "test/data/does-not-exist.crt"})
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist.crt")
}

func TestAPIConfig_IsTLSEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		envs     Envs
		expected bool
	}{
		{
			name: "Should return true when cert and key are set",
			envs: Envs{
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
			},
			expected: true,
		},
		{
			name:     "Should return false when neither cert nor key is set",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			envs := Envs{"SCANNER_STORE_POSTGRES_URL": testDSN}
			for k, v := range tc.envs {
				envs[k] = v
			}
			setenvs(t, envs)
			config, err := GetConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, config.API.IsTLSEnabled())
		})
	}
}

func setenvs(t *testing.T, envs Envs) {
	t.Helper()
	// os.Clearenv wipes TMPDIR along with everything else, and t.TempDir then
	// falls back to /tmp, which is not writable for every user the suite runs
	// as.
	tmpDir := os.Getenv("TMPDIR")
	os.Clearenv()
	if tmpDir != "" {
		require.NoError(t, os.Setenv("TMPDIR", tmpDir))
	}
	for key, value := range envs {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}
