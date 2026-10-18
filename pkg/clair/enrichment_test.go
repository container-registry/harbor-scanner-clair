package clair

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadReport(t *testing.T, name string) *VulnerabilityReport {
	t.Helper()
	var report VulnerabilityReport
	require.NoError(t, json.Unmarshal(fixture(t, name), &report))
	return &report
}

func TestCVSSByVulnIDOnRealOutput(t *testing.T) {
	t.Parallel()

	// Captured from Clair 4.9.0 with updaters.sets [alpine, clair.cvss]. The
	// map key is the vulnerability id, not the CVE name.
	report := loadReport(t, "vulnerability_report_alpine310.json")
	scores := report.CVSSByVulnID()

	require.Len(t, scores, 1)
	score := scores["29602"]
	assert.Equal(t, "3.1", score.Version)
	assert.InDelta(t, 9.1, score.BaseScore, 0.001)
	assert.Equal(t, "CRITICAL", score.BaseSeverity)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", score.VectorString)
	assert.Equal(t, "CVE-2021-36159", report.Vulnerabilities["29602"].Name,
		"the enrichment key is the vulnerabilities map key")
}

func TestCVSSByVulnIDWithoutEnrichments(t *testing.T) {
	t.Parallel()

	// An updater set without clair.cvss produces an empty enrichments map, and
	// findings newer than the NVD feed carry no score either.
	report := loadReport(t, "vulnerability_report_8gcr.json")
	assert.Empty(t, report.CVSSByVulnID())

	assert.Empty(t, (&VulnerabilityReport{}).CVSSByVulnID())

	var nilReport *VulnerabilityReport
	assert.Empty(t, nilReport.CVSSByVulnID())
}

func TestCVSSByVulnIDKeyHandling(t *testing.T) {
	t.Parallel()

	const entry = `{"356835":[{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}]}`

	t.Run("reads the exact key", func(t *testing.T) {
		t.Parallel()
		report := &VulnerabilityReport{Enrichments: map[string][]json.RawMessage{
			CVSSEnrichmentKey: {json.RawMessage(entry)},
		}}
		assert.InDelta(t, 9.8, report.CVSSByVulnID()["356835"].BaseScore, 0.001)
	})

	// The schema URL is part of the key upstream, so a reformat there must not
	// silently drop every score.
	t.Run("falls back to any clair.cvss key", func(t *testing.T) {
		t.Parallel()
		report := &VulnerabilityReport{Enrichments: map[string][]json.RawMessage{
			"message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://example.test/other.schema": {json.RawMessage(entry)},
		}}
		assert.InDelta(t, 9.8, report.CVSSByVulnID()["356835"].BaseScore, 0.001)
	})

	t.Run("ignores enrichers that are not clair.cvss", func(t *testing.T) {
		t.Parallel()
		report := &VulnerabilityReport{Enrichments: map[string][]json.RawMessage{
			"message/vnd.clair.map.vulnerability; enricher=clair.epss schema=https://example.test/epss.schema": {json.RawMessage(`{"356835":[{"epss":0.4}]}`)},
			"message/vnd.clair.map.vulnerability; enricher=clair.kev schema=https://example.test/kev.schema":   {json.RawMessage(`{"356835":[{"kev":true}]}`)},
		}}
		assert.Empty(t, report.CVSSByVulnID())
	})

	t.Run("keeps the highest score for one id", func(t *testing.T) {
		t.Parallel()
		report := &VulnerabilityReport{Enrichments: map[string][]json.RawMessage{
			CVSSEnrichmentKey: {
				json.RawMessage(`{"356835":[{"version":"3.0","baseScore":5.5,"baseSeverity":"MEDIUM"},{"version":"3.1","baseScore":7.8,"baseSeverity":"HIGH"}]}`),
				json.RawMessage(`{"356835":[{"version":"3.1","baseScore":6.1,"baseSeverity":"MEDIUM"}]}`),
			},
		}}
		score := report.CVSSByVulnID()["356835"]
		assert.InDelta(t, 7.8, score.BaseScore, 0.001)
		assert.Equal(t, "HIGH", score.BaseSeverity)
	})

	t.Run("skips an element it cannot decode", func(t *testing.T) {
		t.Parallel()
		report := &VulnerabilityReport{Enrichments: map[string][]json.RawMessage{
			CVSSEnrichmentKey: {json.RawMessage(`["not an object"]`), json.RawMessage(entry)},
		}}
		assert.Len(t, report.CVSSByVulnID(), 1)
	})
}
