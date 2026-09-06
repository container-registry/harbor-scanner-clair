package scan

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden reports in pkg/scan/testdata from the captured Clair fixtures")

type fixedClock struct {
	fixedTime time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.fixedTime
}

// goldenTime is pinned so the golden reports are byte-stable.
var goldenTime = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func v4Transformer() *Transformer {
	return &Transformer{clock: &fixedClock{fixedTime: goldenTime}}
}

func v4Scanner() harbor.Scanner {
	return harbor.Scanner{Name: "Clair", Vendor: "Project Quay", Version: "4.9.0"}
}

func v4Artifact() harbor.Artifact {
	return harbor.Artifact{
		Repository: "library/alpine",
		Digest:     "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
		MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
	}
}

// TestTransformer_Transform_Golden pins the whole report against two
// vulnerability reports captured from a real Clair 4.9.0. Regenerate with
// `go test ./pkg/scan/... -update` and read the diff before committing it.
func TestTransformer_Transform_Golden(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		fixture    string
		golden     string
	}{
		{
			name:       "alpine 3.10, one finding whose severity comes from the CVSS enrichment",
			repository: "library/alpine",
			fixture:    "vulnerability_report_alpine310.json",
			golden:     "report_golden_alpine310.json",
		},
		{
			name:       "adapter image, ten findings across two packages and no enrichment",
			repository: "8gears/harbor-scanner-clair",
			fixture:    "vulnerability_report_8gcr.json",
			golden:     "report_golden_8gcr.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.fixture))
			require.NoError(t, err)

			var report clair.VulnerabilityReport
			require.NoError(t, json.Unmarshal(raw, &report))

			// The artifact mirrors the fixture so the golden report reads as the
			// scan it came from.
			artifact := harbor.Artifact{
				Repository: tc.repository,
				Digest:     report.ManifestHash,
				MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
			}

			got, err := json.MarshalIndent(v4Transformer().Transform(artifact, v4Scanner(), &report), "", "  ")
			require.NoError(t, err)
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", tc.golden)
			if *updateGolden {
				require.NoError(t, os.WriteFile(goldenPath, got, 0o600))
			}

			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err)
			assert.Equal(t, string(want), string(got))
		})
	}
}

func TestTransformer_Transform_Mapping(t *testing.T) {
	tests := []struct {
		name   string
		report *clair.VulnerabilityReport
		want   []harbor.VulnerabilityItem
	}{
		{
			name: "the no-fix sentinel becomes an empty fix version",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{
					"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Low", FixedInVersion: "0"},
					"11": {ID: "11", Name: "CVE-0000-0002", NormalizedSeverity: "Low", FixedInVersion: "1.1.22-r5"},
				},
				map[string][]string{"1": {"10", "11"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevLow, Links: []string{}},
				{ID: "CVE-0000-0002", Pkg: "musl", Version: "1.1.22-r4", FixVersion: "1.1.22-r5", Severity: harbor.SevLow, Links: []string{}},
			},
		},
		{
			name: "links are split on whitespace and never nil",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{
					"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Low", Links: "https://one.example  https://two.example\nhttps://three.example"},
					"11": {ID: "11", Name: "CVE-0000-0002", NormalizedSeverity: "Low", Links: ""},
				},
				map[string][]string{"1": {"10", "11"}},
			),
			want: []harbor.VulnerabilityItem{
				{
					ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevLow,
					Links: []string{"https://one.example", "https://two.example", "https://three.example"},
				},
				{ID: "CVE-0000-0002", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevLow, Links: []string{}},
			},
		},
		{
			name: "Negligible passes through rather than collapsing into Low",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Negligible"}},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevNegligible, Links: []string{}},
			},
		},
		{
			name: "an unrecognized normalized severity is reported as Unknown",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "~~UNRECOGNIZED~~"}},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevUnknown, Links: []string{}},
			},
		},
		{
			name: "the vulnerability id stands in for a missing name",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", NormalizedSeverity: "High"}},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "10", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevHigh, Links: []string{}},
			},
		},
		{
			name: "a package id with no package entry is skipped",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High"}},
				map[string][]string{"1": {"10"}, "999": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevHigh, Links: []string{}},
			},
		},
		{
			name: "a vulnerability id with no vulnerability entry is skipped",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High"}},
				map[string][]string{"1": {"10", "999"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevHigh, Links: []string{}},
			},
		},
		{
			name: "vendor attributes carry the updater, the raw distro severity and the distribution",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"}},
				map[string]*clair.Vulnerability{
					"10": {
						ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High",
						Updater:  "alpine-main-v3.10-updater",
						Severity: "important",
						Dist:     &clair.Distribution{DID: "alpine", Name: "Alpine Linux", VersionID: "3.10", PrettyName: "Alpine Linux v3.10"},
					},
				},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{
					ID: "CVE-0000-0001", Pkg: "openssl", Version: "1.1.1k-r0", Severity: harbor.SevHigh, Links: []string{},
					VendorAttributes: map[string]any{
						"clair": map[string]string{
							"updater":         "alpine-main-v3.10-updater",
							"vendor_severity": "important",
							"distribution":    "Alpine Linux v3.10",
						},
					},
				},
			},
		},
		{
			name: "the distribution falls back to name and version, and empty sub-keys are dropped",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"}},
				map[string]*clair.Vulnerability{
					"10": {
						ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High",
						Dist: &clair.Distribution{DID: "debian", Name: "Debian GNU/Linux", Version: "11 (bullseye)"},
					},
				},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{
					ID: "CVE-0000-0001", Pkg: "openssl", Version: "1.1.1k-r0", Severity: harbor.SevHigh, Links: []string{},
					VendorAttributes: map[string]any{
						"clair": map[string]string{"distribution": "Debian GNU/Linux 11 (bullseye)"},
					},
				},
			},
		},
		{
			name: "vendor attributes are omitted entirely when nothing would go in them",
			report: reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High"}},
				map[string][]string{"1": {"10"}},
			),
			want: []harbor.VulnerabilityItem{
				{ID: "CVE-0000-0001", Pkg: "openssl", Version: "1.1.1k-r0", Severity: harbor.SevHigh, Links: []string{}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := v4Transformer().Transform(v4Artifact(), v4Scanner(), tc.report)
			assert.Equal(t, tc.want, got.Vulnerabilities)
		})
	}
}

// TestTransformer_Transform_CVSSFallback covers the path Alpine content takes:
// Clair normalizes everything to Unknown and the score is the only signal.
func TestTransformer_Transform_CVSSFallback(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
		score      float64
		want       harbor.Severity
	}{
		{name: "10.0 is Critical, the boundary Quay's own mapping loses", normalized: "Unknown", score: 10.0, want: harbor.SevCritical},
		{name: "9.0 is Critical", normalized: "Unknown", score: 9.0, want: harbor.SevCritical},
		{name: "8.9 is High", normalized: "Unknown", score: 8.9, want: harbor.SevHigh},
		{name: "7.0 is High", normalized: "Unknown", score: 7.0, want: harbor.SevHigh},
		{name: "4.0 is Medium", normalized: "Unknown", score: 4.0, want: harbor.SevMedium},
		{name: "3.9 is Low", normalized: "Unknown", score: 3.9, want: harbor.SevLow},
		{name: "0.1 is Low", normalized: "Unknown", score: 0.1, want: harbor.SevLow},
		{name: "0 stays Unknown", normalized: "Unknown", score: 0, want: harbor.SevUnknown},
		{name: "an unrecognized severity takes the fallback too", normalized: "", score: 9.1, want: harbor.SevCritical},
		{name: "a normalized severity wins over the score", normalized: "Low", score: 9.8, want: harbor.SevLow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := reportOf(
				map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}},
				map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: tc.normalized}},
				map[string][]string{"1": {"10"}},
			)
			report.Enrichments = enrichmentsOf(clair.CVSSEnrichmentKey, map[string][]clair.CVSS{
				"10": {{Version: "3.1", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", BaseScore: tc.score, BaseSeverity: "CRITICAL"}},
			})

			got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
			require.Len(t, got.Vulnerabilities, 1)
			assert.Equal(t, tc.want, got.Vulnerabilities[0].Severity)
			assert.Equal(t, tc.want, got.Severity)

			score := float32(tc.score)
			assert.Equal(t, &harbor.CVSSDetails{
				ScoreV3:  &score,
				VectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
			}, got.Vulnerabilities[0].PreferredCVSS)
			assert.Equal(t, map[string]any{
				"CVSS": map[string]cvssInfo{"nvd": {V3Score: &score, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"}},
			}, got.Vulnerabilities[0].VendorAttributes)
		})
	}
}

func TestTransformer_Transform_Enrichments(t *testing.T) {
	packages := map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r4"}}
	vulnerabilities := map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Unknown"}}
	packageVulnerabilities := map[string][]string{"1": {"10"}}

	t.Run("a report with no enrichments keeps Unknown and carries no CVSS", func(t *testing.T) {
		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), reportOf(packages, vulnerabilities, packageVulnerabilities))
		require.Len(t, got.Vulnerabilities, 1)
		assert.Equal(t, harbor.SevUnknown, got.Vulnerabilities[0].Severity)
		assert.Nil(t, got.Vulnerabilities[0].PreferredCVSS)
		assert.Nil(t, got.Vulnerabilities[0].VendorAttributes)
	})

	t.Run("an enrichment key with another schema URL is still recognized", func(t *testing.T) {
		report := reportOf(packages, vulnerabilities, packageVulnerabilities)
		report.Enrichments = enrichmentsOf(
			"message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://example.test/some/other/schema.json",
			map[string][]clair.CVSS{"10": {{Version: "3.1", BaseScore: 7.5}}},
		)

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		require.Len(t, got.Vulnerabilities, 1)
		assert.Equal(t, harbor.SevHigh, got.Vulnerabilities[0].Severity)
	})

	t.Run("the highest score wins when one vulnerability carries several", func(t *testing.T) {
		report := reportOf(packages, vulnerabilities, packageVulnerabilities)
		report.Enrichments = enrichmentsOf(clair.CVSSEnrichmentKey, map[string][]clair.CVSS{
			"10": {{Version: "3.0", BaseScore: 5.3}, {Version: "3.1", BaseScore: 9.8}},
		})

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		require.Len(t, got.Vulnerabilities, 1)
		assert.Equal(t, harbor.SevCritical, got.Vulnerabilities[0].Severity)
	})
}

func TestTransformer_Transform_Dedup(t *testing.T) {
	t.Run("the same package indexed twice yields one row, the worse one", func(t *testing.T) {
		report := reportOf(
			map[string]*clair.Package{
				"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"},
				"2": {ID: "2", Name: "openssl", Version: "1.1.1k-r0"},
			},
			map[string]*clair.Vulnerability{
				"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Low"},
				"11": {ID: "11", Name: "CVE-0000-0001", NormalizedSeverity: "High"},
			},
			map[string][]string{"1": {"10"}, "2": {"11"}},
		)

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		assert.Equal(t, []harbor.VulnerabilityItem{
			{ID: "CVE-0000-0001", Pkg: "openssl", Version: "1.1.1k-r0", Severity: harbor.SevHigh, Links: []string{}},
		}, got.Vulnerabilities)
	})

	t.Run("two packages sharing a CVE stay two rows", func(t *testing.T) {
		report := reportOf(
			map[string]*clair.Package{
				"1": {ID: "1", Name: "libcrypto3", Version: "3.5.7-r0"},
				"2": {ID: "2", Name: "libssl3", Version: "3.5.7-r0"},
			},
			map[string]*clair.Vulnerability{"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "Medium"}},
			map[string][]string{"1": {"10"}, "2": {"10"}},
		)

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		assert.Equal(t, []harbor.VulnerabilityItem{
			{ID: "CVE-0000-0001", Pkg: "libcrypto3", Version: "3.5.7-r0", Severity: harbor.SevMedium, Links: []string{}},
			{ID: "CVE-0000-0001", Pkg: "libssl3", Version: "3.5.7-r0", Severity: harbor.SevMedium, Links: []string{}},
		}, got.Vulnerabilities)
	})

	t.Run("equal severities are separated by the CVSS score", func(t *testing.T) {
		report := reportOf(
			map[string]*clair.Package{
				"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"},
				"2": {ID: "2", Name: "openssl", Version: "1.1.1k-r0"},
			},
			map[string]*clair.Vulnerability{
				"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High", Description: "lower score"},
				"11": {ID: "11", Name: "CVE-0000-0001", NormalizedSeverity: "High", Description: "higher score"},
			},
			map[string][]string{"1": {"10"}, "2": {"11"}},
		)
		report.Enrichments = enrichmentsOf(clair.CVSSEnrichmentKey, map[string][]clair.CVSS{
			"10": {{Version: "3.1", BaseScore: 7.1}},
			"11": {{Version: "3.1", BaseScore: 8.8}},
		})

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		require.Len(t, got.Vulnerabilities, 1)
		assert.Equal(t, "higher score", got.Vulnerabilities[0].Description)
	})

	t.Run("an all-round tie is broken by the smaller vulnerability id", func(t *testing.T) {
		report := reportOf(
			map[string]*clair.Package{
				"1": {ID: "1", Name: "openssl", Version: "1.1.1k-r0"},
				"2": {ID: "2", Name: "openssl", Version: "1.1.1k-r0"},
			},
			map[string]*clair.Vulnerability{
				"10": {ID: "10", Name: "CVE-0000-0001", NormalizedSeverity: "High", Description: "id 10"},
				"11": {ID: "11", Name: "CVE-0000-0001", NormalizedSeverity: "High", Description: "id 11"},
			},
			map[string][]string{"1": {"11"}, "2": {"10"}},
		)

		got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)
		require.Len(t, got.Vulnerabilities, 1)
		assert.Equal(t, "id 10", got.Vulnerabilities[0].Description)
	})
}

func TestTransformer_Transform_RollUpAndOrder(t *testing.T) {
	report := reportOf(
		map[string]*clair.Package{
			"1": {ID: "1", Name: "zlib", Version: "1.2.11"},
			"2": {ID: "2", Name: "musl", Version: "1.1.22-r4"},
			"3": {ID: "3", Name: "musl", Version: "1.1.24-r0"},
		},
		map[string]*clair.Vulnerability{
			"10": {ID: "10", Name: "CVE-0000-0002", NormalizedSeverity: "Medium"},
			"11": {ID: "11", Name: "CVE-0000-0001", NormalizedSeverity: "Critical"},
			"12": {ID: "12", Name: "CVE-0000-0003", NormalizedSeverity: "Medium"},
			"13": {ID: "13", Name: "CVE-0000-0004", NormalizedSeverity: "Negligible"},
		},
		map[string][]string{"1": {"10", "11"}, "2": {"12"}, "3": {"13"}},
	)

	got := v4Transformer().Transform(v4Artifact(), v4Scanner(), report)

	assert.Equal(t, harbor.SevCritical, got.Severity)
	assert.Equal(t, goldenTime, got.GeneratedAt)
	assert.Equal(t, v4Artifact(), got.Artifact)
	assert.Equal(t, v4Scanner(), got.Scanner)

	// Severity descending, then package, version and id ascending.
	var order []string
	for _, item := range got.Vulnerabilities {
		order = append(order, item.Severity.String()+" "+item.Pkg+" "+item.Version+" "+item.ID)
	}
	assert.Equal(t, []string{
		"Critical zlib 1.2.11 CVE-0000-0001",
		"Medium musl 1.1.22-r4 CVE-0000-0003",
		"Medium zlib 1.2.11 CVE-0000-0002",
		"Negligible musl 1.1.24-r0 CVE-0000-0004",
	}, order)
}

func TestTransformer_Transform_EmptyReport(t *testing.T) {
	tests := []struct {
		name   string
		report *clair.VulnerabilityReport
	}{
		{name: "a report with no findings", report: reportOf(nil, nil, nil)},
		{name: "no report at all", report: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := v4Transformer().Transform(v4Artifact(), v4Scanner(), tc.report)

			assert.Equal(t, harbor.SevNone, got.Severity)
			assert.Equal(t, []harbor.VulnerabilityItem{}, got.Vulnerabilities)
			assert.Equal(t, goldenTime, got.GeneratedAt)

			raw, err := json.Marshal(got)
			require.NoError(t, err)
			assert.Contains(t, string(raw), `"severity":"None"`)
			assert.Contains(t, string(raw), `"vulnerabilities":[]`)
		})
	}
}

// TestTransformer_Transform_IgnoresPackageNotVulnerable goes through the wire
// decoding because the field is only ever seen there: the report struct does
// not carry it, so the packages listed under it must not turn into findings.
func TestTransformer_Transform_IgnoresPackageNotVulnerable(t *testing.T) {
	raw := `{
	  "manifest_hash": "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
	  "packages": {
	    "1": {"id": "1", "name": "musl", "version": "1.1.22-r4"},
	    "2": {"id": "2", "name": "zlib", "version": "1.2.11"}
	  },
	  "vulnerabilities": {
	    "10": {"id": "10", "name": "CVE-0000-0001", "normalized_severity": "High"}
	  },
	  "package_vulnerabilities": {"1": ["10"]},
	  "PackageNotVulnerable": {"2": ["10"]}
	}`

	var report clair.VulnerabilityReport
	require.NoError(t, json.Unmarshal([]byte(raw), &report))

	got := v4Transformer().Transform(v4Artifact(), v4Scanner(), &report)
	assert.Equal(t, []harbor.VulnerabilityItem{
		{ID: "CVE-0000-0001", Pkg: "musl", Version: "1.1.22-r4", Severity: harbor.SevHigh, Links: []string{}},
	}, got.Vulnerabilities)
}

func reportOf(
	packages map[string]*clair.Package,
	vulnerabilities map[string]*clair.Vulnerability,
	packageVulnerabilities map[string][]string,
) *clair.VulnerabilityReport {
	return &clair.VulnerabilityReport{
		ManifestHash:           "sha256:e515aad2ed234a5072c4d2ef86a1cb77d5bfe4b11aa865d9214875734c4eeb3c",
		Packages:               packages,
		Vulnerabilities:        vulnerabilities,
		PackageVulnerabilities: packageVulnerabilities,
	}
}

func enrichmentsOf(key string, byVulnID map[string][]clair.CVSS) map[string][]json.RawMessage {
	block, err := json.Marshal(byVulnID)
	if err != nil {
		panic(err)
	}
	return map[string][]json.RawMessage{key: {block}}
}
