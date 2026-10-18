package harbor

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// severityNames covers every declared value. A value missing from
// severityToString renders as "" and Harbor cannot parse the report.
var severityNames = map[Severity]string{
	SevNone:       "None",
	SevUnknown:    "Unknown",
	SevNegligible: "Negligible",
	SevLow:        "Low",
	SevMedium:     "Medium",
	SevHigh:       "High",
	SevCritical:   "Critical",
}

func TestSeverity_RoundTrip(t *testing.T) {
	for severity, name := range severityNames {
		t.Run(name, func(t *testing.T) {
			marshaled, err := json.Marshal(severity)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("%q", name), string(marshaled))
			assert.Equal(t, name, severity.String())

			var back Severity
			require.NoError(t, json.Unmarshal(marshaled, &back))
			assert.Equal(t, severity, back)
		})
	}
}

// TestSeverity_Ordering pins the ascending order the report-level roll-up
// depends on: it is a plain max over the item severities.
func TestSeverity_Ordering(t *testing.T) {
	assert.Less(t, SevNone, SevUnknown)
	assert.Less(t, SevUnknown, SevNegligible)
	assert.Less(t, SevNegligible, SevLow)
	assert.Less(t, SevLow, SevMedium)
	assert.Less(t, SevMedium, SevHigh)
	assert.Less(t, SevHigh, SevCritical)
}

// TestSeverity_UnmarshalUnknownString: an unrecognized name must become Unknown,
// not the zero value. The zero value has no name, so it marshals back as "" and
// silently drops the fact that a severity was reported at all.
func TestSeverity_UnmarshalUnknownString(t *testing.T) {
	for _, value := range []string{`"Moderate"`, `"important"`, `""`} {
		t.Run(value, func(t *testing.T) {
			var severity Severity
			require.NoError(t, json.Unmarshal([]byte(value), &severity))
			assert.Equal(t, SevUnknown, severity)
			assert.Equal(t, "Unknown", severity.String())
		})
	}
}

func TestSeverity_UnmarshalNonString(t *testing.T) {
	var severity Severity
	assert.Error(t, json.Unmarshal([]byte("7"), &severity))
}

// TestClairScanner pins the advertised scanner block. Clair moved to Project
// Quay years ago, and the vendor and generation the v1 adapter reported are both
// stale.
func TestClairScanner(t *testing.T) {
	assert.Equal(t, Scanner{Name: "Clair", Vendor: "Project Quay", Version: "4.x"}, ClairScanner())
}

// TestVulnerabilityItem_JSONShape pins the wire names Harbor reads, including
// preferred_cvss and vendor_attributes, and the absence of a "layer" field.
func TestVulnerabilityItem_JSONShape(t *testing.T) {
	score := float32(9.8)
	item := VulnerabilityItem{
		ID:            "CVE-2019-1111",
		Pkg:           "openssl",
		Version:       "2.0-rc1",
		FixVersion:    "2.1",
		Severity:      SevCritical,
		Description:   "upgrade",
		Links:         []string{"https://example.test/CVE-2019-1111"},
		PreferredCVSS: &CVSSDetails{ScoreV3: &score, VectorV3: "CVSS:3.1/AV:N"},
		VendorAttributes: map[string]any{
			"clair": map[string]any{"updater": "alpine"},
		},
	}
	marshaled, err := json.Marshal(item)
	require.NoError(t, err)

	assert.JSONEq(t, `{
      "id": "CVE-2019-1111",
      "package": "openssl",
      "version": "2.0-rc1",
      "fix_version": "2.1",
      "severity": "Critical",
      "description": "upgrade",
      "links": ["https://example.test/CVE-2019-1111"],
      "preferred_cvss": {"score_v3": 9.8, "vector_v2": "", "vector_v3": "CVSS:3.1/AV:N"},
      "vendor_attributes": {"clair": {"updater": "alpine"}}
    }`, string(marshaled))
	assert.NotContains(t, string(marshaled), "layer")
	assert.NotContains(t, string(marshaled), "status")
}

// TestScanReport_EmptyReportIsNone: a clean artifact reports None, which is a
// value Harbor core accepts (src/pkg/scan/vuln/severity.go).
func TestScanReport_EmptyReportIsNone(t *testing.T) {
	marshaled, err := json.Marshal(ScanReport{Severity: SevNone})
	require.NoError(t, err)
	assert.Contains(t, string(marshaled), `"severity":"None"`)
}
