package clair

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testManifestHash = "sha256:90a4ffb96e4d60d7da32ee758c23ba398cf952715cb8e89bfddf6155dcd7daf6"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// newTestClient points a client at a fake Clair and shrinks the backoff so the
// retry ladders cost milliseconds instead of minutes.
func newTestClient(t *testing.T, handler http.HandlerFunc) *client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	c, err := NewClient(Config{
		URL:                server.URL,
		IndexTimeout:       5 * time.Second,
		RequestTimeout:     5 * time.Second,
		ReportRetryTimeout: 500 * time.Millisecond,
	}, nil)
	require.NoError(t, err)

	impl, ok := c.(*client)
	require.True(t, ok)
	impl.retryInitial = 2 * time.Millisecond
	impl.retryMax = 8 * time.Millisecond
	return impl
}

func testManifest() Manifest {
	return Manifest{
		Hash: testManifestHash,
		Layers: []Layer{{
			Hash:    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			URI:     "https://core.harbor.domain/v2/library/alpine/blobs/sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Headers: map[string][]string{"Authorization": {"Bearer harbor-minted-token"}},
		}},
	}
}

func TestClientIndex(t *testing.T) {
	t.Parallel()

	t.Run("returns the finished report", func(t *testing.T) {
		t.Parallel()
		var body Manifest
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/indexer/api/v1/index_report", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Accept"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(fixture(t, "index_report_finished.json"))
		})

		report, err := c.Index(context.Background(), testManifest())
		require.NoError(t, err)
		assert.Equal(t, StateIndexFinished, report.State)
		assert.True(t, report.Success)
		assert.Equal(t, testManifestHash, report.ManifestHash)
		// The manifest goes out as posted: hash, layer URI and the header map
		// Harbor's token travels in.
		assert.Equal(t, testManifest(), body)
	})

	t.Run("reports an IndexError as a failed index", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(fixture(t, "index_report_error.json"))
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrIndexFailed)
		assert.Contains(t, err.Error(), "401 Unauthorized")
	})

	t.Run("reports a report that is neither finished nor errored", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"manifest_hash":"`+testManifestHash+`","state":"CheckManifest","success":false,"err":""}`)
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrIndexFailed)
		assert.Contains(t, err.Error(), "CheckManifest")
	})

	t.Run("treats a tarfs 400 as an unscannable layer", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"code":"bad_request","message":"tarfs: not a tar: format error"}`)
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrUnscannableLayer)
	})

	t.Run("treats any other 400 as a permanent bad request", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"code":"bad_request","message":"could not deserialize manifest"}`)
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrBadRequest)
		assert.NotErrorIs(t, err, ErrUnscannableLayer)
	})

	t.Run("names the PSK variables on a 401", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrUnauthorized)
		assert.Contains(t, err.Error(), "SCANNER_CLAIR_PSK")
		assert.Contains(t, err.Error(), "SCANNER_CLAIR_JWT_ISSUER")
	})

	t.Run("treats a 412 as already indexed", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusPreconditionFailed)
		})

		report, err := c.Index(context.Background(), testManifest())
		require.NoError(t, err)
		assert.Equal(t, StateIndexFinished, report.State)
		assert.Equal(t, testManifestHash, report.ManifestHash)
		assert.True(t, report.Success)
	})

	t.Run("retries a 429 and backs off before the next attempt", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(fixture(t, "index_report_finished.json"))
		})

		started := time.Now()
		report, err := c.Index(context.Background(), testManifest())
		elapsed := time.Since(started)

		require.NoError(t, err)
		assert.Equal(t, StateIndexFinished, report.State)
		assert.Equal(t, int32(2), calls.Load())
		// Full jitter puts the first delay in [initial/2, initial].
		assert.GreaterOrEqual(t, elapsed, c.retryInitial/2)
	})

	t.Run("honors a Retry-After it can use", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(fixture(t, "index_report_finished.json"))
		})
		// The hint is only used when it fits inside the backoff ceiling.
		c.retryMax = 2 * time.Second

		started := time.Now()
		_, err := c.Index(context.Background(), testManifest())
		elapsed := time.Since(started)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, elapsed, time.Second)
		assert.Less(t, elapsed, 2*time.Second)
	})

	t.Run("gives up on a 500", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"code":"internal","message":"boom"}`)
		})

		_, err := c.Index(context.Background(), testManifest())
		require.ErrorIs(t, err, ErrServerError)
		assert.Equal(t, int32(1), calls.Load(), "a 500 is not retried")
	})
}

func TestClientRetryAfter(t *testing.T) {
	t.Parallel()

	c := &client{retryMax: 30 * time.Second}
	for _, tc := range []struct {
		header   string
		expected time.Duration
	}{
		{header: "", expected: 0},
		{header: "1", expected: time.Second},
		{header: "30", expected: 30 * time.Second},
		{header: "31", expected: 0},
		{header: "0", expected: 0},
		{header: "-5", expected: 0},
		{header: "Wed, 21 Oct 2015 07:28:00 GMT", expected: 0},
	} {
		t.Run("Retry-After: "+tc.header, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{Header: http.Header{}}
			if tc.header != "" {
				resp.Header.Set("Retry-After", tc.header)
			}
			assert.Equal(t, tc.expected, c.retryAfter(resp))
		})
	}
}

func TestClientVulnerabilityReport(t *testing.T) {
	t.Parallel()

	t.Run("decodes a real report", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/matcher/api/v1/vulnerability_report/"+testManifestHash, r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Accept"))
			// 4.9.0 labels the vulnerability report as an index report. The
			// client must not gate on that.
			w.Header().Set("Content-Type", "application/vnd.clair.index_report.v1+json")
			_, _ = w.Write(fixture(t, "vulnerability_report_alpine310.json"))
		})

		report, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.NoError(t, err)
		require.Len(t, report.Vulnerabilities, 1)
		vuln := report.Vulnerabilities["29602"]
		require.NotNil(t, vuln)
		assert.Equal(t, "CVE-2021-36159", vuln.Name)
		assert.Equal(t, "Unknown", vuln.NormalizedSeverity)
		assert.Equal(t, "2.10.7-r0", vuln.FixedInVersion)
		assert.Equal(t, "https://security.alpinelinux.org/vuln/CVE-2021-36159", vuln.Links)
		require.NotNil(t, vuln.Dist)
		assert.Equal(t, "alpine", vuln.Dist.DID)
		assert.Equal(t, "3.10", vuln.Dist.VersionID)
		assert.Equal(t, []string{"29602"}, report.PackageVulnerabilities["174"])
		assert.Equal(t, "apk-tools", report.Packages["174"].Name)
	})

	t.Run("waits out a matcher that is still loading", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_, _ = w.Write(fixture(t, "vulnerability_report_alpine310.json"))
		})

		report, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.NoError(t, err)
		assert.Len(t, report.Vulnerabilities, 1)
		assert.Equal(t, int32(3), calls.Load())
	})

	t.Run("gives up on a matcher that never initializes", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		})
		c.reportRetryTimeout = 30 * time.Millisecond

		_, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.ErrorIs(t, err, ErrMatcherNotReady)
	})

	t.Run("takes the third 404 at face value", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNotFound)
		})

		_, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.ErrorIs(t, err, ErrNotIndexed)
		assert.Equal(t, int32(reportNotFoundAttempts), calls.Load())
	})

	t.Run("rejects a report whose Clair-Error trailer is set", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			// Declaring the trailer forces a chunked response, which is what
			// makes a trailer possible at all.
			w.Header().Set("Trailer", "Clair-Error")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fixture(t, "vulnerability_report_alpine310.json"))
			w.Header().Set(http.TrailerPrefix+"Clair-Error", "matcher: context deadline exceeded")
		})

		_, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.ErrorIs(t, err, ErrReportTruncated)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})

	t.Run("rejects a body that stops mid-report", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, `{"manifest_hash":"`+testManifestHash+`","packages":{"174":{"id":"174"`)
		})

		_, err := c.VulnerabilityReport(context.Background(), testManifestHash)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrReportTruncated)
		assert.Contains(t, err.Error(), "decoding vulnerability report")
	})
}

func TestClientMatcherReady(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		status   int
		expected bool
	}{
		{name: "202 while the matcher has no data", status: http.StatusAccepted, expected: false},
		{name: "404 once the matcher answers", status: http.StatusNotFound, expected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/matcher/api/v1/vulnerability_report/"+readinessDigest, r.URL.Path)
				w.WriteHeader(tc.status)
			})

			ready, err := c.MatcherReady(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.expected, ready)
		})
	}

	t.Run("surfaces an unexpected status", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, err := c.MatcherReady(context.Background())
		require.ErrorIs(t, err, ErrServerError)
	})
}

func TestClientIndexState(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/indexer/api/v1/index_state", r.URL.Path)
		w.Header().Set("Etag", `"aae368a064d7c5a433d0bf2c4f5554cc"`)
		_, _ = fmt.Fprint(w, `{"state":"aae368a064d7c5a433d0bf2c4f5554cc"}`)
	})

	state, err := c.IndexState(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "aae368a064d7c5a433d0bf2c4f5554cc", state)
}

func TestClientVulnDBUpdatedAt(t *testing.T) {
	t.Parallel()

	const operations = `{
	  "alpine-main-v3.10-updater": [{"ref":"1","updater":"alpine-main-v3.10-updater","date":"2026-09-05T14:52:11.7Z","kind":"vulnerability"}],
	  "alpine-main-v3.20-updater": [{"ref":"2","updater":"alpine-main-v3.20-updater","date":"2026-09-05T15:01:44.2Z","kind":"vulnerability"}]
	}`

	t.Run("reports the newest update operation", func(t *testing.T) {
		t.Parallel()
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/matcher/api/v1/internal/update_operation", r.URL.Path)
			assert.Equal(t, "true", r.URL.Query().Get("latest"))
			assert.Equal(t, "vulnerability", r.URL.Query().Get("kind"))
			_, _ = fmt.Fprint(w, operations)
		})

		at, ok, err := c.VulnDBUpdatedAt(context.Background())
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "2026-09-05T15:01:44.2Z", at.UTC().Format(time.RFC3339Nano))
	})

	// The endpoint is documented as internal and may not exist at all in combo
	// mode, so its absence must never fail a metadata request.
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(fmt.Sprintf("degrades silently on %d", status), func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})

			at, ok, err := c.VulnDBUpdatedAt(context.Background())
			require.NoError(t, err)
			assert.False(t, ok)
			assert.True(t, at.IsZero())
		})
	}

	t.Run("caches the value it found", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = fmt.Fprint(w, operations)
		})

		first, ok, err := c.VulnDBUpdatedAt(context.Background())
		require.NoError(t, err)
		require.True(t, ok)
		second, ok, err := c.VulnDBUpdatedAt(context.Background())
		require.NoError(t, err)
		require.True(t, ok)

		assert.Equal(t, first, second)
		assert.Equal(t, int32(1), calls.Load(), "Harbor calls /metadata on every page load")
	})

	t.Run("keeps serving the last good value when a refresh fails", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				_, _ = fmt.Fprint(w, operations)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})

		first, ok, err := c.VulnDBUpdatedAt(context.Background())
		require.NoError(t, err)
		require.True(t, ok)

		// Age the cache past its TTL so the next call goes back to Clair.
		c.mu.Lock()
		c.vulnDBFetchedAt = time.Now().Add(-2 * vulnDBCacheTTL)
		c.mu.Unlock()

		second, ok, err := c.VulnDBUpdatedAt(context.Background())
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, first, second)
		assert.Equal(t, int32(2), calls.Load())
	})
}

func TestNewClientRejectsUnusableConfig(t *testing.T) {
	t.Parallel()

	t.Run("empty URL", func(t *testing.T) {
		t.Parallel()
		_, err := NewClient(Config{}, nil)
		require.Error(t, err)
	})

	t.Run("PSK that is not base64", func(t *testing.T) {
		t.Parallel()
		_, err := NewClient(Config{URL: "http://clair:6060", PSK: "not base64!", Issuer: "harbor-scanner-clair"}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SCANNER_CLAIR_PSK")
	})

	t.Run("PSK without an issuer", func(t *testing.T) {
		t.Parallel()
		_, err := NewClient(Config{URL: "http://clair:6060", PSK: "c2VjcmV0"}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SCANNER_CLAIR_JWT_ISSUER")
	})

	t.Run("timeouts fall back to the defaults", func(t *testing.T) {
		t.Parallel()
		c, err := NewClient(Config{URL: "http://clair:6060"}, nil)
		require.NoError(t, err)
		impl, ok := c.(*client)
		require.True(t, ok)
		assert.Equal(t, defaultIndexTimeout, impl.indexTimeout)
		assert.Equal(t, defaultRequestTimeout, impl.requestTimeout)
		assert.Equal(t, defaultReportRetryTimeout, impl.reportRetryTimeout)
	})
}
