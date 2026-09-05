// Package harbor holds the Harbor Scanner Adapter API v1 domain models used by
// this adapter. It is ported from harbor-scanner-trivy with the SBOM types
// stripped: Clair produces vulnerability reports only, so the adapter
// advertises a single "vulnerability" capability.
package harbor

import (
	"bytes"
	"encoding/json"
	"time"
)

// Severity represents the severity of an image/component in terms of
// vulnerability.
type Severity int

// Sevxxx is the list of severities an artifact can carry after scanning. The
// set is Harbor core's own (src/pkg/scan/vuln/severity.go), which is also
// exactly Clair's normalized_severity set plus None. The ordering is what makes
// the report-level roll-up a plain max, so it must stay ascending.
const (
	_ Severity = iota
	// SevNone is report-level only: an artifact with no vulnerabilities. Using
	// it rather than the zero value keeps the roll-up from marshaling as "".
	SevNone
	SevUnknown
	SevNegligible
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

// severityToString has an entry for every declared value. A missing entry
// renders as the empty string, and Harbor rejects a report whose severity it
// cannot parse.
var severityToString = map[Severity]string{
	SevNone:       "None",
	SevUnknown:    "Unknown",
	SevNegligible: "Negligible",
	SevLow:        "Low",
	SevMedium:     "Medium",
	SevHigh:       "High",
	SevCritical:   "Critical",
}

var stringToSeverity = map[string]Severity{
	"None":       SevNone,
	"Unknown":    SevUnknown,
	"Negligible": SevNegligible,
	"Low":        SevLow,
	"Medium":     SevMedium,
	"High":       SevHigh,
	"Critical":   SevCritical,
}

// MarshalJSON marshals the enum as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals a quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	// An unrecognized name becomes Unknown, not the zero value: the zero value
	// has no name at all, so it round-trips to "" and loses the fact that a
	// severity was reported.
	severity, ok := stringToSeverity[value]
	if !ok {
		severity = SevUnknown
	}
	*s = severity
	return nil
}

// CapabilityType is the scan type a capability covers. Harbor matches it when
// dispatching a scan (src/controller/scan/checker.go).
type CapabilityType string

const (
	CapabilityTypeVulnerability CapabilityType = "vulnerability"
	CapabilityTypeSBOM          CapabilityType = "sbom"
)

const (
	scannerName   = "Clair"
	scannerVendor = "Project Quay"
	// scannerVersion is the Clair generation this adapter speaks, not a release
	// number: Clair 4.9.0 has no version endpoint and sets no version header,
	// and its OpenAPI info.version is the API version (1.2.0), not the release.
	scannerVersion = "4.x"
)

// ClairScanner is the scanner block advertised in /api/v1/metadata and stamped
// into every report. It is a constant rather than an environment read so the
// value Harbor sees in a report is the one it saw in the metadata.
func ClairScanner() Scanner {
	return Scanner{Name: scannerName, Vendor: scannerVendor, Version: scannerVersion}
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        Artifact            `json:"artifact"`
	Scanner         Scanner             `json:"scanner"`
	Severity        Severity            `json:"severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// CVSSDetails is the preferred_cvss block Harbor renders in the artifact view
// (harbor/src/pkg/scan/vuln/report.go). The v2 fields are declared because
// Harbor reads them; Clair's CVSS enricher collects 3.1/3.0 metrics only, so
// this adapter never populates them.
type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

// VulnerabilityItem is one entry in the vulnerability report. There is no
// "layer" field: it is not part of the Scanners API, and Clair reports findings
// against the whole manifest rather than a layer.
type VulnerabilityItem struct {
	ID               string         `json:"id"`
	Pkg              string         `json:"package"`
	Version          string         `json:"version"`
	FixVersion       string         `json:"fix_version,omitempty"`
	Severity         Severity       `json:"severity"`
	Description      string         `json:"description"`
	Links            []string       `json:"links"`
	PreferredCVSS    *CVSSDetails   `json:"preferred_cvss,omitempty"`
	CweIDs           []string       `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]any `json:"vendor_attributes,omitempty"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// Capability is both the /metadata advertisement and the enabled_capabilities
// entry Harbor sends on /scan. The MIME lists are plain strings (Harbor's own
// ScannerCapability shape) so an unservable value reaches the validator as a
// 422 rather than failing at JSON unmarshal as a 400.
type Capability struct {
	Type              CapabilityType `json:"type"`
	ConsumesMIMETypes []string       `json:"consumes_mime_types"`
	ProducesMIMETypes []string       `json:"produces_mime_types"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}
