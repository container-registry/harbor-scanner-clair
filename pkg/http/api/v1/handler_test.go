package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
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

type stubClair struct {
	updatedAt *time.Time
	err       error
}

func (c *stubClair) ScanLayer(clair.Layer) error { return nil }
func (c *stubClair) GetLayer(string) (*clair.LayerEnvelope, error) {
	return nil, nil
}

func (c *stubClair) GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error) {
	return c.updatedAt, c.err
}

func TestRequestHandler_GetHealthy(t *testing.T) {
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/probe/healthy", nil)
	require.NoError(t, err)

	NewAPIHandler(&stubClair{}, &stubEnqueuer{}, &stubStore{}, nil).ServeHTTP(rr, r)

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
			ready:          func(context.Context) error { return errors.New("the database is down") },
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, "/probe/ready", nil)
			require.NoError(t, err)

			NewAPIHandler(&stubClair{}, &stubEnqueuer{}, &stubStore{}, tc.ready).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	validScanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Basic dXNlcjpwYXNzd29yZAo=",
		},
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		},
	}
	validScanRequestJSON := `{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Basic dXNlcjpwYXNzd29yZAo="
  },
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  }
}`

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
			name:                "Should respond with error 422 when scan request's registry URL is blank",
			requestBody:         `{"registry":{}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing registry.url"),
		},
		{
			name:                "Should respond with error 422 when scan request's registry URL is invalid",
			requestBody:         `{"registry":{"url":"INVALID URL"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid registry.url"),
		},
		{
			name:                "Should respond with error 422 when scan request's artifact repository is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.repository"),
		},
		{
			name:                "Should respond with error 422 when scan request's artifact digest is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}, "artifact":{"repository":"library/mongo"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.digest"),
		},
		{
			name:                "Should respond with error 500 when the job cannot be queued",
			enqueuer:            &stubEnqueuer{err: errors.New("clair is down")},
			requestBody:         validScanRequestJSON,
			expectedEnqueued:    true,
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse:    errorJSON("performing scan: clair is down"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enqueuer := tc.enqueuer
			if enqueuer == nil {
				enqueuer = &stubEnqueuer{}
			}

			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.requestBody))
			require.NoError(t, err)

			NewAPIHandler(&stubClair{}, enqueuer, &stubStore{}, nil).ServeHTTP(rr, r)

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

func TestRequestHandler_GetScanReport(t *testing.T) {
	now := time.Now()
	report := harbor.ScanReport{
		GeneratedAt: now,
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		},
		Scanner: harbor.Scanner{
			Name:    "Clair",
			Vendor:  "CoreOS",
			Version: "2.x",
		},
		Severity: harbor.SevCritical,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:          "CVE-2019-1111",
				Pkg:         "openssl",
				Version:     "2.0-rc1",
				FixVersion:  "2.1",
				Severity:    harbor.SevCritical,
				Description: "You'd better upgrade your server",
				Links:       []string{"http://cve.com?id=CVE-2019-1111"},
			},
		},
	}
	reportJSON, err := json.Marshal(report)
	require.NoError(t, err)

	testCases := []struct {
		name                 string
		store                *stubStore
		expectedStatus       int
		expectedContentType  string
		expectedRefreshAfter string
		expectedResponse     string
	}{
		{
			name:                "Should respond with error 500 when retrieving scan job fails",
			store:               &stubStore{err: errors.New("data store is down")},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse:    errorJSON("getting scan job: data store is down"),
		},
		{
			name:                "Should respond with error 404 when scan job cannot be found",
			store:               &stubStore{},
			expectedStatus:      http.StatusNotFound,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
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
				ID:     "job:123",
				Status: job.Failed,
				Error:  "worker failed",
			}},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse:    errorJSON("worker failed"),
		},
		{
			name: fmt.Sprintf("Should respond with error 500 when scan job is NOT %s", job.Finished),
			store: &stubStore{scanJob: &job.ScanJob{
				ID:     "job:123",
				Status: 666,
			}},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse:    errorJSON("unexpected status Unknown of scan job job:123"),
		},
		{
			name: "Should respond with vulnerabilities report",
			store: &stubStore{scanJob: &job.ScanJob{
				ID:     "job:123",
				Status: job.Finished,
				Report: reportJSON,
			}},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
			expectedResponse:    string(reportJSON),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r, rErr := http.NewRequest(http.MethodGet, "/api/v1/scan/job:123/report", nil)
			require.NoError(t, rErr)

			NewAPIHandler(&stubClair{}, &stubEnqueuer{}, tc.store, nil).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))
			assert.Equal(t, tc.expectedRefreshAfter, rr.Header().Get(api.HeaderRefreshAfter))
			assert.Equal(t, "job:123", tc.store.gotID)
			if tc.expectedResponse != "" {
				assert.JSONEq(t, tc.expectedResponse, rr.Body.String())
			}
		})
	}
}

func TestRequestHandler_GetMetadata(t *testing.T) {
	updatedAt, err := time.Parse(time.RFC3339, "2014-11-12T11:45:26Z")
	require.NoError(t, err)

	t.Run("Should report the vulnerability database timestamp when it is known", func(t *testing.T) {
		rr := httptest.NewRecorder()
		r, rErr := http.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
		require.NoError(t, rErr)

		NewAPIHandler(&stubClair{updatedAt: &updatedAt}, &stubEnqueuer{}, &stubStore{}, nil).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.JSONEq(t, `{
  "scanner": {
    "name": "Clair",
    "vendor": "CoreOS",
    "version": "2.x"
  },
  "capabilities": [
    {
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
      ]
    }
  ],
  "properties": {
    "harbor.scanner-adapter/vulnerability-database-updated-at": "2014-11-12T11:45:26Z",
    "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
    "harbor.scanner-adapter/registry-authorization-type": "Bearer"
  }
}`, rr.Body.String())
	})

	// Harbor's Validate() rejects an empty property value, so an unknown
	// timestamp must omit the property rather than report a zero time.
	t.Run("Should omit the timestamp property when it is unknown", func(t *testing.T) {
		rr := httptest.NewRecorder()
		r, rErr := http.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
		require.NoError(t, rErr)

		NewAPIHandler(&stubClair{}, &stubEnqueuer{}, &stubStore{}, nil).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusOK, rr.Code)
		var metadata harbor.ScannerMetadata
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &metadata))
		assert.NotContains(t, metadata.Properties, "harbor.scanner-adapter/vulnerability-database-updated-at")
	})
}

func errorJSON(message string) string {
	return fmt.Sprintf(`{"error":{"message":%q}}`, message)
}
