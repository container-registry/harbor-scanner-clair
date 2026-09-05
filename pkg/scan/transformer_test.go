package scan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

type fixedClock struct {
	fixedTime time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.fixedTime
}

func TestTransformer_ToHarborScanReport(t *testing.T) {
	transformer := NewTransformer()
	fixedTime := time.Now()
	transformer.clock = &fixedClock{fixedTime: fixedTime}

	artifact := harbor.Artifact{
		Repository: "library/cassandra",
		Digest:     "sha256:70acd789bbbe58a2bbad70880e0ee1dc131846bd2f6c5f5ba459bad8a5b94815",
		MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
	}
	source := &clair.VulnerabilityReport{
		Packages: map[string]*clair.Package{
			"1": {ID: "1", Name: "e2fsprogs", Version: "1.43.4-2"},
			"2": {ID: "2", Name: "glibc", Version: "2.24-11+deb9u4"},
			"3": {ID: "3", Name: "apk-tools", Version: "2.10.4-r3"},
		},
		Vulnerabilities: map[string]*clair.Vulnerability{
			"10": {
				ID:                 "10",
				Name:               "CVE-2019-5094",
				Description:        "CVE-2019-5094 desc",
				Links:              "https://security-tracker.debian.org/tracker/CVE-2019-5094",
				NormalizedSeverity: "Medium",
				FixedInVersion:     "1.43.4-2+deb9u1",
			},
			"11": {
				ID:                 "11",
				Name:               "CVE-2019-1010023",
				Description:        "CVE-2019-1010023 desc",
				Links:              "https://security-tracker.debian.org/tracker/CVE-2019-1010023 https://example.test/mirror",
				NormalizedSeverity: "Negligible",
				// "0" is Clair's no-fix sentinel and must not reach Harbor.
				FixedInVersion: "0",
			},
			"12": {
				ID:                 "12",
				Name:               "CVE-2018-6485",
				Description:        "CVE-2018-6485 desc",
				NormalizedSeverity: "Critical",
			},
			"13": {
				ID:                 "13",
				Name:               "CVE-2021-36159",
				Description:        "",
				NormalizedSeverity: "Unknown",
			},
		},
		PackageVulnerabilities: map[string][]string{
			"1": {"10"},
			"2": {"11", "12"},
			"3": {"13"},
			// A package the report does not describe is skipped rather than
			// rendered as an empty package name.
			"99": {"10"},
		},
	}

	scanReport := transformer.ToHarborScanReport(testScanner(), artifact, source)

	assert.Equal(t, harbor.ScanReport{
		GeneratedAt: fixedTime,
		Artifact: harbor.Artifact{
			Repository: "library/cassandra",
			Digest:     "sha256:70acd789bbbe58a2bbad70880e0ee1dc131846bd2f6c5f5ba459bad8a5b94815",
			MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
		},
		Scanner:  harbor.ClairScanner(),
		Severity: harbor.SevCritical,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:          "CVE-2021-36159",
				Pkg:         "apk-tools",
				Version:     "2.10.4-r3",
				Severity:    harbor.SevUnknown,
				Description: "",
				Links:       []string{},
			},
			{
				ID:          "CVE-2019-5094",
				Pkg:         "e2fsprogs",
				Version:     "1.43.4-2",
				FixVersion:  "1.43.4-2+deb9u1",
				Severity:    harbor.SevMedium,
				Description: "CVE-2019-5094 desc",
				Links:       []string{"https://security-tracker.debian.org/tracker/CVE-2019-5094"},
			},
			{
				ID:          "CVE-2018-6485",
				Pkg:         "glibc",
				Version:     "2.24-11+deb9u4",
				Severity:    harbor.SevCritical,
				Description: "CVE-2018-6485 desc",
				Links:       []string{},
			},
			{
				ID:          "CVE-2019-1010023",
				Pkg:         "glibc",
				Version:     "2.24-11+deb9u4",
				Severity:    harbor.SevNegligible,
				Description: "CVE-2019-1010023 desc",
				// links is space-separated on the wire.
				Links: []string{
					"https://security-tracker.debian.org/tracker/CVE-2019-1010023",
					"https://example.test/mirror",
				},
			},
		},
	}, scanReport)
}

func TestTransformer_ToHarborScanReportWithoutFindings(t *testing.T) {
	transformer := NewTransformer()
	fixedTime := time.Now()
	transformer.clock = &fixedClock{fixedTime: fixedTime}

	report := transformer.ToHarborScanReport(testScanner(), harbor.Artifact{}, &clair.VulnerabilityReport{})

	assert.Equal(t, harbor.SevNone, report.Severity)
	assert.Empty(t, report.Vulnerabilities)
	assert.NotNil(t, report.Vulnerabilities, "an empty report must marshal as [] rather than null")
}

func TestToHarborSeverity(t *testing.T) {
	// Clair's normalized_severity vocabulary is exactly Harbor's, so this is an
	// identity mapping.
	for normalized, expected := range map[string]harbor.Severity{
		"Negligible":       harbor.SevNegligible,
		"Low":              harbor.SevLow,
		"Medium":           harbor.SevMedium,
		"High":             harbor.SevHigh,
		"Critical":         harbor.SevCritical,
		"Unknown":          harbor.SevUnknown,
		"":                 harbor.SevUnknown,
		"~~UNRECOGNIZED~~": harbor.SevUnknown,
	} {
		assert.Equal(t, expected, toHarborSeverity(normalized), "normalized_severity %q", normalized)
	}
}
