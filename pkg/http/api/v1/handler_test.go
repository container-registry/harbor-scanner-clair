package v1

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/http/api"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
)

// The stubs below replace the generated mock package. Each records what the
// handler asked for so a test can assert on it without a mocking framework.

type stubEnqueuer struct {
	gotRequest harbor.ScanRequest
	called     bool
	id         string
	err        error
}

func (e *stubEnqueuer) Enqueue(_ context.Context, request harbor.ScanRequest) (string, error) {
	e.called = true
	e.gotRequest = request
	return e.id, e.err
}

type stubStore struct {
	gotID   string
	scanJob *job.ScanJob
	err     error
}

func (s *stubStore) Create(context.Context, job.ScanJob) error { return nil }

func (s *stubStore) Get(_ context.Context, scanJobID string) (*job.ScanJob, error) {
	s.gotID = scanJobID
	return s.scanJob, s.err
}

func (s *stubStore) UpdateStatus(context.Context, string, job.ScanJobStatus, ...string) error {
	return nil
}
func (s *stubStore) Finish(context.Context, string, json.RawMessage) error { return nil }
func (s *stubStore) FailIfQueued(context.Context, string, string) error    { return nil }

func testConfig(t *testing.T) etc.Config {
	t.Helper()
	// The handler never touches the store; the memory backend keeps GetConfig
	// from demanding a Postgres DSN.
	t.Setenv("SCANNER_STORE_BACKEND", "memory")
	config, err := etc.GetConfig()
	require.NoError(t, err)
	config.Clair.URL = "http://clair:6060"
	config.API.MetricsEnabled = false
	// Hermetic against ambient env: a SCANNER_API_AUTH_API_KEY set in the
	// developer's shell would otherwise arm the auth middleware and 401 every
	// test that does not send the header.
	config.API.APIKey = ""
	return config
}

var testBuildInfo = etc.BuildInfo{Version: "1.2.3", Commit: "deadbee", Date: "2026-09-05"}

func newHandler(t *testing.T, store *stubStore, enqueuer *stubEnqueuer, ready ReadyFunc) http.Handler {
	t.Helper()
	return NewAPIHandler(testBuildInfo, testConfig(t), harbor.ClairScanner(), enqueuer, store, ready, nil)
}

const validDigest = "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"

func errorJSON(message string) string {
	return fmt.Sprintf(`{"error":{"message":%q}}`, message)
}

func TestRequestHandler_GetHealthy(t *testing.T) {
	rr := httptest.NewRecorder()
	newHandler(t, &stubStore{}, &stubEnqueuer{}, nil).
		ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/probe/healthy", nil))
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRequestHandler_GetReady covers both arms of the injected readiness check:
// a dependency that cannot be reached must answer 503 so an orchestrator stops
// routing scans at this replica, not 200.
func TestRequestHandler_GetReady(t *testing.T) {
	testCases := []struct {
		name           string
		ready          ReadyFunc
		expectedStatus int
	}{
		{
			name:           "Should respond 200 when no readiness check is wired",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Should respond 200 when the readiness check passes",
			ready:          func(context.Context) error { return nil },
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Should respond 503 when the readiness check fails",
			ready:          func(context.Context) error { return errors.New("matcher is still initializing") },
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			newHandler(t, &stubStore{}, &stubEnqueuer{}, tc.ready).
				ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/probe/ready", nil))
			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	validScanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig",
		},
		Artifact: harbor.Artifact{Repository: "library/mongo", Digest: validDigest},
	}
	validScanRequestJSON := fmt.Sprintf(`{
  "registry": {"url": "https://core.harbor.domain", "authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig"},
  "artifact": {"repository": "library/mongo", "digest": %q}
}`, validDigest)

	testCases := []struct {
		name                string
		enqueuer            *stubEnqueuer
		requestBody         string
		expectedEnqueued    bool
		expectedStatus      int
		expectedContentType string
		expectedResponse    string
	}{
		{
			name:                "Should accept scan request",
			enqueuer:            &stubEnqueuer{id: "sr:123"},
			requestBody:         validScanRequestJSON,
			expectedEnqueued:    true,
			expectedStatus:      http.StatusAccepted,
			expectedContentType: "application/vnd.scanner.adapter.scan.response+json; version=1.0",
			expectedResponse:    `{"id": "sr:123"}`,
		},
		{
			name:                "Should respond with error 400 when scan request cannot be parsed",
			requestBody:         "THIS AIN'T PARSE",
			expectedStatus:      http.StatusBadRequest,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("unmarshalling scan request: invalid character 'T' looking for beginning of value"),
		},
		{
			name:                "Should respond with error 422 when registry URL is blank",
			requestBody:         `{"registry":{}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing registry.url"),
		},
		{
			name:                "Should respond with error 422 when registry URL is unparseable",
			requestBody:         `{"registry":{"url":"INVALID URL"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid registry.url: expected an absolute http(s) URL"),
		},
		{
			name:                "Should respond with error 422 when registry URL has no scheme",
			requestBody:         `{"registry":{"url":"core.harbor.domain"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid registry.url: expected an absolute http(s) URL"),
		},
		{
			name:                "Should respond with error 422 when registry URL scheme is not http(s)",
			requestBody:         `{"registry":{"url":"ftp://core.harbor.domain"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid registry.url: expected an absolute http(s) URL"),
		},
		{
			name:                "Should respond with error 422 when artifact repository is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.repository"),
		},
		{
			name:                "Should respond with error 422 when artifact digest is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}, "artifact":{"repository":"library/mongo"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.digest"),
		},
		{
			// An unparseable digest used to be 202-accepted and failed only once
			// a worker picked the job up, where Harbor reads it as a scan
			// failure rather than as the bad request it is.
			name:                "Should respond with error 422 when artifact digest is malformed",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}, "artifact":{"repository":"library/mongo","digest":"not-a-digest"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid artifact.digest: invalid checksum digest format"),
		},
		{
			name:                "Should respond with error 422 when artifact digest is not sha256",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}, "artifact":{"repository":"library/mongo","digest":"sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON(`unsupported artifact.digest algorithm "sha512": only sha256 is supported`),
		},
		{
			name:                "Should respond with error 422 when the sbom capability is requested",
			requestBody:         fmt.Sprintf(`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":%q},"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"]}]}`, validDigest),
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("this adapter only produces vulnerability reports; register an SBOM-capable adapter (trivy, dependency-track) for sbom generation"),
		},
		{
			name:                "Should respond with error 422 when an unknown capability type is requested",
			requestBody:         fmt.Sprintf(`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":%q},"enabled_capabilities":[{"type":"license"}]}`, validDigest),
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON(`unsupported scan type: "license"`),
		},
		{
			name:                "Should respond with error 422 when an unservable produces mime type is requested",
			requestBody:         fmt.Sprintf(`{"registry":{"url":"https://c"},"artifact":{"repository":"a","digest":%q},"enabled_capabilities":[{"type":"vulnerability","produces_mime_types":["application/vnd.example+json"]}]}`, validDigest),
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON(`unsupported produces mime type: "application/vnd.example+json"`),
		},
		{
			name:                "Should respond with error 422 when the authorization is not Bearer",
			requestBody:         fmt.Sprintf(`{"registry":{"url":"https://c","authorization":"Basic dXNlcjpwYXNz"},"artifact":{"repository":"a","digest":%q}}`, validDigest),
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse: errorJSON("invalid registry.authorization; this adapter advertises Bearer registry authorization -- " +
				"a non-Bearer authorization indicates a misconfigured scanner registration"),
		},
		{
			name:                "Should respond with error 422 when the authorization has no credentials",
			requestBody:         fmt.Sprintf(`{"registry":{"url":"https://c","authorization":"Bearer"},"artifact":{"repository":"a","digest":%q}}`, validDigest),
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse: errorJSON("invalid registry.authorization; this adapter advertises Bearer registry authorization -- " +
				"a non-Bearer authorization indicates a misconfigured scanner registration"),
		},
		{
			name:                "Should respond with error 500 when the job cannot be queued",
			enqueuer:            &stubEnqueuer{err: errors.New("redis is down")},
			requestBody:         validScanRequestJSON,
			expectedEnqueued:    true,
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("enqueuing scan job: redis is down"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enqueuer := tc.enqueuer
			if enqueuer == nil {
				enqueuer = &stubEnqueuer{}
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.requestBody))
			newHandler(t, &stubStore{}, enqueuer, nil).ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))
			assert.JSONEq(t, tc.expectedResponse, rr.Body.String())

			assert.Equal(t, tc.expectedEnqueued, enqueuer.called)
			if tc.expectedEnqueued {
				assert.Equal(t, validScanRequest, enqueuer.gotRequest)
			}
		})
	}
}

// TestRequestHandler_AcceptScanRequestAnonymous: an empty authorization is an
// anonymous pull from a public project, which Harbor does send.
func TestRequestHandler_AcceptScanRequestAnonymous(t *testing.T) {
	body := fmt.Sprintf(`{"registry":{"url":"https://c","authorization":""},"artifact":{"repository":"a","digest":%q}}`, validDigest)
	rr := httptest.NewRecorder()
	newHandler(t, &stubStore{}, &stubEnqueuer{id: "sr:1"}, nil).
		ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body)))
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func reportRequest(id string, accept string, gzipAccept bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/"+id+"/report", nil)
	if accept != "" {
		req.Header.Set(api.HeaderAccept, accept)
	}
	if gzipAccept {
		req.Header.Set(api.HeaderAcceptEncoding, "gzip")
	}
	return req
}

func TestRequestHandler_GetScanReport(t *testing.T) {
	reportJSON := json.RawMessage(`{"generated_at":"2026-09-05T10:00:00Z","severity":"Critical","vulnerabilities":[]}`)

	testCases := []struct {
		name                 string
		accept               string
		store                *stubStore
		expectedStatus       int
		expectedContentType  string
		expectedRefreshAfter string
		expectedResponse     string
	}{
		{
			// No Accept means "anything you produce"; there is one report type.
			name:   "Should serve the vulnerability report when the Accept header is missing",
			accept: "-",
			store: &stubStore{scanJob: &job.ScanJob{
				ID: "job:123", Status: job.Finished, Report: reportJSON,
			}},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/vnd.security.vulnerability.report; version=1.1",
			expectedResponse:    string(reportJSON),
		},
		{
			name:                "Should respond with error 415 when the Accept header is a report type the adapter does not produce",
			accept:              "application/vnd.security.sbom.report+json; version=1.0",
			store:               &stubStore{},
			expectedStatus:      http.StatusUnsupportedMediaType,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON(`unsupported media type: "application/vnd.security.sbom.report+json; version=1.0"`),
		},
		{
			name:                "Should respond with error 500 when retrieving scan job fails",
			store:               &stubStore{err: errors.New("data store is down")},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("getting scan job: data store is down"),
		},
		{
			name:                "Should respond with error 404 when scan job cannot be found",
			store:               &stubStore{},
			expectedStatus:      http.StatusNotFound,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("cannot find scan job: job:123"),
		},
		{
			// Harbor parses Refresh-After with ParseInt(v, 10, 8), so a value
			// above 127 is silently discarded and Harbor falls back to its own
			// interval.
			name:                 fmt.Sprintf("Should respond with found status 302 when scan job is %s", job.Queued),
			store:                &stubStore{scanJob: &job.ScanJob{ID: "job:123", Status: job.Queued}},
			expectedStatus:       http.StatusFound,
			expectedRefreshAfter: "5",
		},
		{
			name:                 fmt.Sprintf("Should respond with found status 302 when scan job is %s", job.Pending),
			store:                &stubStore{scanJob: &job.ScanJob{ID: "job:123", Status: job.Pending}},
			expectedStatus:       http.StatusFound,
			expectedRefreshAfter: "5",
		},
		{
			name: fmt.Sprintf("Should respond with error 500 when scan job is %s", job.Failed),
			store: &stubStore{scanJob: &job.ScanJob{
				ID: "job:123", Status: job.Failed, Error: "[clair_index] indexing failed: tarfs",
			}},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("[clair_index] indexing failed: tarfs"),
		},
		{
			name:                "Should respond with error 500 when scan job status is unknown",
			store:               &stubStore{scanJob: &job.ScanJob{ID: "job:123", Status: 666}},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("unexpected status Unknown of scan job job:123"),
		},
		{
			name: "Should respond with the stored vulnerability report",
			store: &stubStore{scanJob: &job.ScanJob{
				ID: "job:123", Status: job.Finished, Report: reportJSON,
			}},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/vnd.security.vulnerability.report; version=1.1",
			expectedResponse:    string(reportJSON),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accept := tc.accept
			switch accept {
			case "":
				accept = api.MimeTypeSecurityVulnerabilityReport.String()
			case "-": // the sentinel for "send no Accept header"
				accept = ""
			}

			rr := httptest.NewRecorder()
			newHandler(t, tc.store, &stubEnqueuer{}, nil).ServeHTTP(rr, reportRequest("job:123", accept, false))

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))
			assert.Equal(t, tc.expectedRefreshAfter, rr.Header().Get(api.HeaderRefreshAfter))
			if tc.expectedStatus == http.StatusFound {
				assert.NotEmpty(t, rr.Header().Get("Location"))
			}
			if tc.expectedResponse != "" {
				assert.JSONEq(t, tc.expectedResponse, rr.Body.String())
			}
		})
	}
}

// TestRequestHandler_GetScanReportGzip: the report path streams stored bytes,
// compressed when the client asked for it, rather than re-marshaling per poll.
func TestRequestHandler_GetScanReportGzip(t *testing.T) {
	reportJSON := json.RawMessage(`{"severity":"None","vulnerabilities":[]}`)
	store := &stubStore{scanJob: &job.ScanJob{ID: "job:123", Status: job.Finished, Report: reportJSON}}

	rr := httptest.NewRecorder()
	newHandler(t, store, &stubEnqueuer{}, nil).
		ServeHTTP(rr, reportRequest("job:123", api.MimeTypeSecurityVulnerabilityReport.String(), true))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "gzip", rr.Header().Get(api.HeaderContentEncoding))

	gz, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	require.NoError(t, err)
	decoded, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.JSONEq(t, string(reportJSON), string(decoded))
}

func TestRequestHandler_GetMetadata(t *testing.T) {
	updatedAt, err := time.Parse(time.RFC3339, "2026-09-04T11:45:26Z")
	require.NoError(t, err)

	metadataRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
	}

	t.Run("Should serve the advertised capability and properties", func(t *testing.T) {
		handler := NewAPIHandler(testBuildInfo, testConfig(t), harbor.ClairScanner(), &stubEnqueuer{}, &stubStore{}, nil,
			func(context.Context) (time.Time, bool) { return updatedAt, true })

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, metadataRequest())

		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, api.MimeTypeMetadata.String(), rr.Header().Get("Content-Type"))
		assert.JSONEq(t, `{
  "scanner": {"name": "Clair", "vendor": "Project Quay", "version": "4.x"},
  "capabilities": [
    {
      "type": "vulnerability",
      "consumes_mime_types": [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.vulnerability.report; version=1.1"
      ]
    }
  ],
  "properties": {
    "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
    "harbor.scanner-adapter/registry-authorization-type": "Bearer",
    "harbor.scanner-adapter/vulnerability-database-updated-at": "2026-09-04T11:45:26Z",
    "org.label-schema.version": "1.2.3",
    "org.label-schema.build-date": "2026-09-05",
    "org.label-schema.vcs-ref": "deadbee",
    "org.label-schema.vcs": "https://github.com/container-registry/harbor-scanner-clair",
    "env.SCANNER_CLAIR_URL": "http://clair:6060"
  }
}`, rr.Body.String())
	})

	// A zero timestamp in the Harbor UI reads as a stale vulnerability
	// database, so an unavailable answer omits the property instead.
	t.Run("Should omit the timestamp property when the provider cannot answer", func(t *testing.T) {
		handler := NewAPIHandler(testBuildInfo, testConfig(t), harbor.ClairScanner(), &stubEnqueuer{}, &stubStore{}, nil,
			func(context.Context) (time.Time, bool) { return time.Time{}, false })

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, metadataRequest())

		require.Equal(t, http.StatusOK, rr.Code)
		var metadata harbor.ScannerAdapterMetadata
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &metadata))
		assert.NotContains(t, metadata.Properties, "harbor.scanner-adapter/vulnerability-database-updated-at")
	})

	t.Run("Should omit the timestamp property when no provider is injected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		newHandler(t, &stubStore{}, &stubEnqueuer{}, nil).ServeHTTP(rr, metadataRequest())

		require.Equal(t, http.StatusOK, rr.Code)
		var metadata harbor.ScannerAdapterMetadata
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &metadata))
		assert.NotContains(t, metadata.Properties, "harbor.scanner-adapter/vulnerability-database-updated-at")
	})
}

// TestAPIKeyMiddleware pins that the key guards /api/v1 only: an orchestrator
// probing readiness and a Prometheus scrape cannot send the header.
func TestAPIKeyMiddleware(t *testing.T) {
	config := testConfig(t)
	config.API.APIKey = "the-key"
	config.API.MetricsEnabled = true
	handler := NewAPIHandler(testBuildInfo, config, harbor.ClairScanner(), &stubEnqueuer{}, &stubStore{},
		func(context.Context) error { return nil }, nil)

	t.Run("missing key is 401", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.JSONEq(t, errorJSON("invalid api key"), rr.Body.String())
	})

	t.Run("wrong key is 401", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
		req.Header.Set("X-ScannerAdapter-API-Key", "nope")
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("correct key is 200", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
		req.Header.Set("X-ScannerAdapter-API-Key", "the-key")
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("probes and metrics stay unauthenticated", func(t *testing.T) {
		for _, path := range []string{"/probe/healthy", "/probe/ready", "/metrics"} {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusOK, rr.Code, path)
		}
	})
}

// TestMetricsEndpointGating: SCANNER_API_SERVER_METRICS_ENABLED=false must not
// route /metrics at all, rather than serve an empty body.
func TestMetricsEndpointGating(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		rr := httptest.NewRecorder()
		newHandler(t, &stubStore{}, &stubEnqueuer{}, nil).
			ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("enabled", func(t *testing.T) {
		config := testConfig(t)
		config.API.MetricsEnabled = true
		handler := NewAPIHandler(testBuildInfo, config, harbor.ClairScanner(), &stubEnqueuer{}, &stubStore{}, nil, nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
