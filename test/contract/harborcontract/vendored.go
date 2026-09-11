// Package harborcontract is a VERBATIM VENDORED COPY of the Harbor contract types
// this adapter must satisfy, pinned in-repo as a test fixture (not a Harbor
// module dependency). Sources, copied unchanged except for dropping Harbor's
// internal error/ORM imports:
//
//   - ScannerAdapterMetadata, ScannerCapability, Scanner, Validate(),
//     isSupportedMimeType, supportedMimeTypes, the MimeType* constants:
//     harbor/src/pkg/scan/rest/v1/{models.go,spec.go}
//
// supportedMimeTypes keeps Harbor's SBOM entry even though this adapter never
// produces one: the point of the copy is that Validate() behaves here exactly as
// it does inside Harbor.
//
// If Harbor changes these, the vendored copy must be re-synced and the contract
// tests re-run. Keeping the copy verbatim is the point: the tests fail loudly if
// the adapter drifts from what Harbor actually parses/validates.
package harborcontract

import (
	"errors"
	"fmt"
	"slices"
)

// --- harbor/src/pkg/scan/rest/v1/spec.go (verbatim constant values) ---

const (
	// MimeTypeDockerArtifact defines the mime type for docker artifact
	MimeTypeDockerArtifact = "application/vnd.docker.distribution.manifest.v2+json"
	// MimeTypeNativeReport defines the mime type for native report
	MimeTypeNativeReport = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	// MimeTypeSBOMReport
	MimeTypeSBOMReport = "application/vnd.security.sbom.report+json; version=1.0"
	// MimeTypeGenericVulnerabilityReport defines the MIME type for the generic report with enhanced information
	MimeTypeGenericVulnerabilityReport = "application/vnd.security.vulnerability.report; version=1.1"
)

// --- harbor/src/pkg/scan/rest/v1/models.go (verbatim) ---

var supportedMimeTypes = []string{
	MimeTypeNativeReport,
	MimeTypeGenericVulnerabilityReport,
	MimeTypeSBOMReport,
}

// Scanner represents metadata of a Scanner Adapter.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// ScannerCapability consists of the set of recognized artifact MIME types and the
// set of scanner report MIME types.
type ScannerCapability struct {
	Type              string   `json:"type"`
	ConsumesMimeTypes []string `json:"consumes_mime_types"`
	ProducesMimeTypes []string `json:"produces_mime_types"`
}

// ScannerProperties is a set of custom properties.
type ScannerProperties map[string]string

// ScannerAdapterMetadata represents metadata of a Scanner Adapter.
type ScannerAdapterMetadata struct {
	Scanner      *Scanner             `json:"scanner"`
	Capabilities []*ScannerCapability `json:"capabilities"`
	Properties   ScannerProperties    `json:"properties"`
}

// Validate validate the metadata
func (md *ScannerAdapterMetadata) Validate() error {
	if md.Scanner == nil ||
		len(md.Scanner.Name) == 0 ||
		len(md.Scanner.Version) == 0 ||
		len(md.Scanner.Vendor) == 0 {
		return errors.New("invalid scanner in metadata")
	}

	if len(md.Capabilities) == 0 {
		return errors.New("invalid capabilities in metadata")
	}

	for _, ca := range md.Capabilities {
		found := slices.Contains(ca.ConsumesMimeTypes, MimeTypeDockerArtifact)
		if !found {
			return fmt.Errorf("missing %s in consumes_mime_types", MimeTypeDockerArtifact)
		}

		found = slices.ContainsFunc(ca.ProducesMimeTypes, func(pm string) bool {
			return isSupportedMimeType(pm)
		})
		if !found {
			return fmt.Errorf("missing %s or %s in produces_mime_types", MimeTypeNativeReport, MimeTypeGenericVulnerabilityReport)
		}
	}

	return nil
}

func isSupportedMimeType(mimeType string) bool {
	return slices.Contains(supportedMimeTypes, mimeType)
}
