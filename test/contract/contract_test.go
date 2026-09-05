package contract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/http/api"
	v1 "github.com/container-registry/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
	"github.com/container-registry/harbor-scanner-clair/test/contract/harborcontract"
)

// These are the exact contract strings Harbor uses. They are duplicated here as
// literals (not imported) so a drift in the adapter's constants is caught.
const (
	exactProducesVulnerabilityReport = "application/vnd.security.vulnerability.report; version=1.1"
	exactConsumesDockerV2            = "application/vnd.docker.distribution.manifest.v2+json"
	exactConsumesOCI                 = "application/vnd.oci.image.manifest.v1+json"
)

type nopEnqueuer struct{}

func (nopEnqueuer) Enqueue(context.Context, harbor.ScanRequest) (string, error) { return "", nil }

func newMetadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("SCANNER_STORE_BACKEND", "memory")
	config, err := etc.GetConfig()
	require.NoError(t, err)
	config.API.MetricsEnabled = false
	config.API.APIKey = ""

	info := etc.BuildInfo{Version: "9.9.9", Commit: "abcdef", Date: "2026-09-05"}
	updatedAt := time.Date(2026, 9, 4, 11, 45, 26, 0, time.UTC)
	handler := v1.NewAPIHandler(info, config, harbor.ClairScanner(), nopEnqueuer{}, memory.NewStore(), nil,
		func(context.Context) (time.Time, bool) { return updatedAt, true })
	return httptest.NewServer(handler)
}

// TestMetadataPassesVendoredHarborValidate proves the served /metadata document
// passes a vendored copy of Harbor's ScannerAdapterMetadata.Validate() and pins
// the exact MIME strings, including the "; version=1.1" parameter.
func TestMetadataPassesVendoredHarborValidate(t *testing.T) {
	srv := newMetadataServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/metadata")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, api.MimeTypeMetadata.String(), resp.Header.Get("Content-Type"))

	var vendored harborcontract.ScannerAdapterMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&vendored))
	require.NoError(t, vendored.Validate(), "served metadata must pass Harbor's Validate()")

	require.Len(t, vendored.Capabilities, 1, "exactly one capability")
	capability := vendored.Capabilities[0]
	assert.Equal(t, "vulnerability", capability.Type)

	require.Len(t, capability.ProducesMimeTypes, 1)
	assert.Equal(t, exactProducesVulnerabilityReport, capability.ProducesMimeTypes[0])

	// consumes = docker manifest v2 + oci image manifest, and no index types:
	// Harbor fans an index out to its child manifests itself when it finds the
	// index media type unsupported.
	assert.Equal(t, []string{exactConsumesDockerV2, exactConsumesOCI}, capability.ConsumesMimeTypes)

	// The vendored Validate() requires the docker manifest v2 type in every
	// capability's consumes list, so pin it separately from the slice compare.
	assert.Contains(t, capability.ConsumesMimeTypes, harborcontract.MimeTypeDockerArtifact)
	assert.Equal(t, harborcontract.MimeTypeGenericVulnerabilityReport, capability.ProducesMimeTypes[0])

	assert.Equal(t, "Bearer", vendored.Properties["harbor.scanner-adapter/registry-authorization-type"])
	assert.Equal(t, "os-package-vulnerability", vendored.Properties["harbor.scanner-adapter/scanner-type"])
	assert.Equal(t, "9.9.9", vendored.Properties["org.label-schema.version"])

	require.NotNil(t, vendored.Scanner)
	assert.Equal(t, "Clair", vendored.Scanner.Name)
	assert.Equal(t, "Project Quay", vendored.Scanner.Vendor)
	assert.Equal(t, "4.x", vendored.Scanner.Version)
}

// TestMetadataRejectedWithoutDockerConsumes proves the vendored Validate() is
// doing real work: dropping the docker manifest type fails it.
func TestMetadataRejectedWithoutDockerConsumes(t *testing.T) {
	metadata := harborcontract.ScannerAdapterMetadata{
		Scanner: &harborcontract.Scanner{Name: "Clair", Vendor: "Project Quay", Version: "4.x"},
		Capabilities: []*harborcontract.ScannerCapability{{
			Type:              "vulnerability",
			ConsumesMimeTypes: []string{exactConsumesOCI},
			ProducesMimeTypes: []string{exactProducesVulnerabilityReport},
		}},
	}
	require.Error(t, metadata.Validate())
}
