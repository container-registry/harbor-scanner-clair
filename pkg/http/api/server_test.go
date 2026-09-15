package api

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// TestNewServer_TLSHardeningOnlyOnTheTLSBranch: ListenAndServe ignores
// TLSConfig entirely, so hardening applied on the plaintext branch does nothing.
func TestNewServer_TLSHardeningOnlyOnTheTLSBranch(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		server, err := NewServer(etc.APIConfig{Addr: ":8080"}, http.NotFoundHandler())
		require.NoError(t, err)
		assert.Nil(t, server.server.TLSConfig)
	})

	t.Run("tls", func(t *testing.T) {
		server, err := NewServer(etc.APIConfig{
			Addr:           ":8443",
			TLSCertificate: "/certs/tls.crt",
			TLSKey:         "/certs/tls.key",
		}, http.NotFoundHandler())
		require.NoError(t, err)
		require.NotNil(t, server.server.TLSConfig)
		assert.Equal(t, uint16(tls.VersionTLS12), server.server.TLSConfig.MinVersion)
		assert.Equal(t, tls.NoClientCert, server.server.TLSConfig.ClientAuth)
	})
}

// TestNewServer_ClientCAs pins the empty-pool trap: AppendCertsFromPEM reports
// whether it added anything, and ignoring it left an empty pool paired with
// RequireAndVerifyClientCert, which rejects every client certificate.
func TestNewServer_ClientCAs(t *testing.T) {
	t.Run("unreadable bundle fails construction", func(t *testing.T) {
		_, err := NewServer(etc.APIConfig{
			TLSCertificate: "/certs/tls.crt",
			TLSKey:         "/certs/tls.key",
			ClientCAs:      []string{filepath.Join(t.TempDir(), "missing.crt")},
		}, http.NotFoundHandler())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not read file")
	})

	t.Run("bundle without a certificate fails construction", func(t *testing.T) {
		path := writeFile(t, "empty.crt", "not a certificate\n")
		_, err := NewServer(etc.APIConfig{
			TLSCertificate: "/certs/tls.crt",
			TLSKey:         "/certs/tls.key",
			ClientCAs:      []string{path},
		}, http.NotFoundHandler())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contains no usable certificate")
	})
}
