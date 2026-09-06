package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExactMimeStrings pins the exact contract MIME strings, including the
// version parameter on the vulnerability report type. Harbor compares these
// byte for byte (src/pkg/scan/rest/v1/spec.go).
func TestExactMimeStrings(t *testing.T) {
	assert.Equal(t, "application/vnd.security.vulnerability.report; version=1.1", MimeTypeSecurityVulnerabilityReport.String())
	assert.Equal(t, "application/vnd.scanner.adapter.metadata+json; version=1.0", MimeTypeMetadata.String())
	assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", MimeTypeScanResponse.String())
	assert.Equal(t, "application/vnd.scanner.adapter.error; version=1.0", MimeTypeError.String())
	assert.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", MimeTypeDockerImageManifestV2.String())
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", MimeTypeOCIImageManifest.String())
}

func TestMIMEType_Parse(t *testing.T) {
	t.Run("vulnerability report with version param", func(t *testing.T) {
		var mt MIMEType
		require.NoError(t, mt.Parse("application/vnd.security.vulnerability.report; version=1.1"))
		assert.True(t, mt.Equal(MimeTypeSecurityVulnerabilityReport))
	})
	t.Run("vulnerability report without params", func(t *testing.T) {
		var mt MIMEType
		require.NoError(t, mt.Parse("application/vnd.security.vulnerability.report"))
		assert.True(t, mt.Equal(MimeTypeSecurityVulnerabilityReport))
	})
	t.Run("legacy native report rejected", func(t *testing.T) {
		var mt MIMEType
		require.Error(t, mt.Parse("application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"))
	})
	t.Run("sbom report rejected", func(t *testing.T) {
		var mt MIMEType
		require.Error(t, mt.Parse("application/vnd.security.sbom.report+json; version=1.0"))
	})
}

// TestMIMEType_ParseAcceptsLegalSpellings pins that a client is not punished for
// formatting a header the way RFC 9110 allows. An exact-string switch only
// matched this adapter's own rendering, so a missing space after ";" -- which
// plenty of clients emit -- produced a 415 for a valid request.
func TestMIMEType_ParseAcceptsLegalSpellings(t *testing.T) {
	for _, value := range []string{
		"application/vnd.security.vulnerability.report; version=1.1",
		"application/vnd.security.vulnerability.report;version=1.1",
		"application/vnd.security.vulnerability.report;  version=1.1",
		"  application/vnd.security.vulnerability.report ; version=1.1  ",
		"APPLICATION/VND.SECURITY.VULNERABILITY.REPORT; VERSION=1.1",
		"application/vnd.security.vulnerability.report",
		"",
		"*/*",
	} {
		t.Run(value, func(t *testing.T) {
			var mt MIMEType
			require.NoError(t, mt.Parse(value))
			assert.Equal(t, MimeTypeSecurityVulnerabilityReport.Subtype, mt.Subtype)
		})
	}
}

func TestMIMEType_ParseRejectsOthers(t *testing.T) {
	for _, value := range []string{
		"application/json",
		"application/vnd.security.vulnerability.report; version=2.0",
		"not a media type all ///",
	} {
		t.Run(value, func(t *testing.T) {
			var mt MIMEType
			assert.Error(t, mt.Parse(value))
		})
	}
}

func TestMIMEType_StringEmpty(t *testing.T) {
	var mt MIMEType
	assert.Empty(t, mt.String())
}

// TestClientAcceptsGzipHonorsQValues: "gzip;q=0" is the explicit way to refuse
// an encoding, and a substring match read it as acceptance -- so a client that
// said it could not decompress received a compressed report.
func TestClientAcceptsGzipHonorsQValues(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"gzip", true},
		{"gzip, deflate", true},
		{"gzip;q=1.0", true},
		{"gzip;q=0.5", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"deflate, gzip;q=0", false},
		{"*", true},
		{"*;q=0", false},
		{"*, gzip;q=0", false},
		{"identity", false},
		{"", false},
		{"GZIP", true},
	}
	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set(HeaderAcceptEncoding, tc.header)
			}
			assert.Equal(t, tc.want, clientAcceptsGzip(req))
		})
	}
}

func TestBaseHandler_WriteJSONError(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	handler.WriteJSONError(recorder, Error{HTTPCode: http.StatusBadRequest, Message: "Invalid request"})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Equal(t, MimeTypeError.String(), recorder.Header().Get(HeaderContentType))
	assert.JSONEq(t, `{"error":{"message":"Invalid request"}}`, recorder.Body.String())
}

func TestBaseHandler_WriteRawJSON(t *testing.T) {
	handler := &BaseHandler{}
	payload := []byte(`{"severity":"None"}`)

	t.Run("plain", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler.WriteRawJSON(recorder, httptest.NewRequest(http.MethodGet, "/", nil),
			payload, MimeTypeSecurityVulnerabilityReport, http.StatusOK)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, MimeTypeSecurityVulnerabilityReport.String(), recorder.Header().Get(HeaderContentType))
		assert.Empty(t, recorder.Header().Get(HeaderContentEncoding))
		assert.JSONEq(t, string(payload), recorder.Body.String())
	})
}
