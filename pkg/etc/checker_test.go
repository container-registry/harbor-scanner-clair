package etc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubPinger struct {
	err    error
	called bool
}

func (p *stubPinger) Ping(context.Context) error {
	p.called = true
	return p.err
}

func TestCheck(t *testing.T) {
	t.Run("Should pass on a usable environment", func(t *testing.T) {
		setenvs(t, Envs{"SCANNER_STORE_BACKEND": "memory"})
		config, err := GetConfig()
		require.NoError(t, err)

		clairPinger := &stubPinger{}
		require.NoError(t, Check(context.Background(), config, nil, clairPinger))
		assert.True(t, clairPinger.called, "the indexer is checked whatever the store backend is")
	})

	// An unreachable Clair means every scan fails, so the adapter must not come
	// up and report itself healthy.
	t.Run("Should fail when clair's indexer does not answer", func(t *testing.T) {
		setenvs(t, Envs{"SCANNER_STORE_BACKEND": "memory", "SCANNER_CLAIR_URL": "http://clair.invalid:6060"})
		config, err := GetConfig()
		require.NoError(t, err)

		err = Check(context.Background(), config, nil, &stubPinger{err: errors.New("connection refused")})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clair's indexer not reachable at http://clair.invalid:6060")
		assert.Contains(t, err.Error(), "SCANNER_CLAIR_URL")
	})

	t.Run("Should ping the store only on the postgres backend", func(t *testing.T) {
		for _, tc := range []struct {
			backend      string
			expectCalled bool
		}{
			{StoreBackendPostgres, true},
			{StoreBackendMemory, false},
		} {
			t.Run(tc.backend, func(t *testing.T) {
				setenvs(t, Envs{"SCANNER_STORE_BACKEND": tc.backend, "SCANNER_STORE_POSTGRES_URL": testDSN})
				config, err := GetConfig()
				require.NoError(t, err)

				store := &stubPinger{}
				require.NoError(t, Check(context.Background(), config, store, &stubPinger{}))
				assert.Equal(t, tc.expectCalled, store.called)
			})
		}
	})

	t.Run("Should fail when postgres does not answer", func(t *testing.T) {
		setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN})
		config, err := GetConfig()
		require.NoError(t, err)

		err = Check(context.Background(), config, &stubPinger{err: errors.New("i/o timeout")}, &stubPinger{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "postgres not reachable at localhost:5432/scanner")
		assert.Contains(t, err.Error(), "SCANNER_STORE_POSTGRES_URL")
	})

	// The DSN carries the password, and this error string ends up in a log
	// aggregator, so the endpoint is rendered rather than the raw value.
	t.Run("Should not leak the password in the postgres error", func(t *testing.T) {
		setenvs(t, Envs{"SCANNER_STORE_POSTGRES_URL": testDSN})
		config, err := GetConfig()
		require.NoError(t, err)

		err = Check(context.Background(), config, &stubPinger{err: errors.New("i/o timeout")}, &stubPinger{})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "scanner:scanner@")
	})

	// A Secret mounted with the wrong mode passes a stat and fails the TLS
	// handshake, which surfaces as a per-client error long after startup.
	t.Run("Should fail on unreadable TLS material", func(t *testing.T) {
		dir := t.TempDir()
		cert := filepath.Join(dir, "tls.crt")
		key := filepath.Join(dir, "tls.key")
		require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

		setenvs(t, Envs{
			"SCANNER_STORE_BACKEND":              "memory",
			"SCANNER_API_SERVER_TLS_CERTIFICATE": cert,
			"SCANNER_API_SERVER_TLS_KEY":         key,
		})
		config, err := GetConfig()
		require.NoError(t, err)

		err = Check(context.Background(), config, nil, &stubPinger{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS private key")
	})

	// An unparseable client CA bundle yields an empty pool, and an empty pool
	// with RequireAndVerifyClientCert rejects every client certificate.
	t.Run("Should fail on an unparseable client CA bundle", func(t *testing.T) {
		dir := t.TempDir()
		cert := filepath.Join(dir, "tls.crt")
		key := filepath.Join(dir, "tls.key")
		bundle := filepath.Join(dir, "ca.crt")
		for _, path := range []string{cert, key} {
			require.NoError(t, os.WriteFile(path, []byte("material"), 0o600))
		}
		require.NoError(t, os.WriteFile(bundle, []byte("not a certificate"), 0o600))

		setenvs(t, Envs{
			"SCANNER_STORE_BACKEND":              "memory",
			"SCANNER_API_SERVER_TLS_CERTIFICATE": cert,
			"SCANNER_API_SERVER_TLS_KEY":         key,
			"SCANNER_API_SERVER_CLIENT_CAS":      bundle,
		})
		config, err := GetConfig()
		require.NoError(t, err)

		err = Check(context.Background(), config, nil, &stubPinger{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contains no usable certificate")
	})

	t.Run("Should accept the client CA fixture", func(t *testing.T) {
		dir := t.TempDir()
		cert := filepath.Join(dir, "tls.crt")
		key := filepath.Join(dir, "tls.key")
		for _, path := range []string{cert, key} {
			require.NoError(t, os.WriteFile(path, []byte("material"), 0o600))
		}

		setenvs(t, Envs{
			"SCANNER_STORE_BACKEND":              "memory",
			"SCANNER_API_SERVER_TLS_CERTIFICATE": cert,
			"SCANNER_API_SERVER_TLS_KEY":         key,
			"SCANNER_API_SERVER_CLIENT_CAS":      filepath.Join("test", "data", "ca.crt"),
		})
		config, err := GetConfig()
		require.NoError(t, err)

		require.NoError(t, Check(context.Background(), config, nil, &stubPinger{}))
	})
}
