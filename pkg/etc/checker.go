package etc

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// Pinger is satisfied by anything the adapter must reach before it can serve a
// scan: the Postgres store, and Clair's indexer.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Check fails fast on an unusable environment: TLS material must be readable
// and parseable, Postgres must answer when it is the store backend, and Clair's
// indexer must answer at all.
//
// The Clair check pings the indexer, never the matcher. On a fresh Clair the
// matcher stays uninitialized for its whole first updater cycle, which is tens
// of minutes, and failing startup on that would crash-loop the adapter for the
// duration. Matcher readiness belongs in /probe/ready, where it is a 503 rather
// than a restart.
func Check(ctx context.Context, config Config, store Pinger, clairIndexer Pinger) error {
	slog.Debug("Current process", slog.Int("pid", os.Getpid()))
	slog.Debug("Current user",
		slog.Int("uid", os.Getuid()),
		slog.Int("gid", os.Getegid()),
		slog.String("home_dir", os.Getenv("HOME")),
	)

	if config.API.IsTLSEnabled() {
		if err := checkReadable(config.API.TLSCertificate); err != nil {
			return fmt.Errorf("TLS certificate %s: %w", config.API.TLSCertificate, err)
		}
		if err := checkReadable(config.API.TLSKey); err != nil {
			return fmt.Errorf("TLS private key %s: %w", config.API.TLSKey, err)
		}
		for _, path := range config.API.ClientCAs {
			if err := checkCertBundle(path); err != nil {
				return fmt.Errorf("client CA %s: %w", path, err)
			}
		}
	}

	if config.TLS.InsecureSkipVerify {
		slog.Warn("TLS verification is DISABLED for Clair and the registry (SCANNER_TLS_INSECURE_SKIP_VERIFY); " +
			"use SCANNER_TLS_CLIENTCAS in production")
	}

	if config.Store.Backend == StoreBackendPostgres && store != nil {
		endpoint := postgresEndpoint(config.Postgres.URL)
		if err := store.Ping(ctx); err != nil {
			return fmt.Errorf("postgres not reachable at %s (check SCANNER_STORE_POSTGRES_URL): %w", endpoint, err)
		}
		slog.Info("postgres is reachable", slog.String("endpoint", endpoint))
	}

	if clairIndexer != nil {
		if err := clairIndexer.Ping(ctx); err != nil {
			return fmt.Errorf("clair's indexer not reachable at %s "+
				"(check SCANNER_CLAIR_URL, and SCANNER_CLAIR_PSK / SCANNER_CLAIR_JWT_ISSUER if Clair requires authentication): %w",
				config.Clair.URL, err)
		}
		slog.Info("clair's indexer is reachable",
			slog.String("url", config.Clair.URL),
			slog.Bool("psk_enabled", config.Clair.IsPSKEnabled()))
	}

	return nil
}

// checkReadable opens the file rather than stat-ing it. A stat passes on a file
// the process cannot read -- the usual case being a Secret mounted with the
// wrong mode or fsGroup -- and the failure then surfaced on the first scan or on
// the TLS handshake instead of at startup.
func checkReadable(name string) error {
	info, err := os.Stat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory, not a file")
	}
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	return f.Close()
}

// checkCertBundle additionally parses the bundle. An unparseable CA file yields
// an empty pool, and an empty pool with RequireAndVerifyClientCert rejects every
// client certificate -- a total outage that presents as a per-client TLS error.
func checkCertBundle(name string) error {
	if err := checkReadable(name); err != nil {
		return err
	}
	pem, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return fmt.Errorf("contains no usable certificate")
	}
	return nil
}

// postgresEndpoint renders the DSN as host:port/database. The raw value carries
// the password, and both the startup error and the log line it feeds end up in
// somebody's log aggregator.
func postgresEndpoint(dsn string) string {
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		// Unreachable in practice: validate() parses the same DSN first.
		return "the configured database"
	}
	return net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port))) + "/" + parsed.Database
}
