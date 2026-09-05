package clair

import (
	"encoding/json"
	"strings"
)

// CVSSEnrichmentKey is claircore's enricher/cvss Type constant, byte for byte
// (note the "; " and the single spaces around "schema="). Verified against the
// claircore v1.5.48 that Clair 4.9.0 ships and on the wire.
const CVSSEnrichmentKey = `message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema`

// cvssEnricherMarker identifies the same enricher when the schema URL in the
// key changes upstream.
const cvssEnricherMarker = "enricher=clair.cvss"

// CVSS is one NVD 2.0 cvssData object. Only 3.1/3.0 Primary metrics are ever
// present: the enricher keeps a single metric per vulnerability, so there is no
// v2 score anywhere downstream.
type CVSS struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CVSSByVulnID flattens the CVSS enrichment block.
//
// The map is keyed by the vulnerability id, which is the key of the report's
// vulnerabilities map, NOT the CVE name: claircore builds it as
// m[id] = append(m[id], r.Enrichment) over the report's vulnerabilities. When
// one id carries several entries the highest baseScore wins, as Quay does.
// A report without enrichments (matcher.disable_enrichment, or an updater set
// without clair.cvss) is normal and yields an empty map.
func (r *VulnerabilityReport) CVSSByVulnID() map[string]CVSS {
	out := make(map[string]CVSS)
	if r == nil || len(r.Enrichments) == 0 {
		return out
	}

	entries, ok := r.Enrichments[CVSSEnrichmentKey]
	if !ok {
		for key, value := range r.Enrichments {
			if strings.Contains(key, cvssEnricherMarker) {
				entries = value
				break
			}
		}
	}

	for _, entry := range entries {
		// Upstream emits exactly one element, but the wire type is a list and
		// nothing enforces that, so every element is merged.
		var byID map[string][]CVSS
		if err := json.Unmarshal(entry, &byID); err != nil {
			continue
		}
		for id, scores := range byID {
			for _, score := range scores {
				if current, seen := out[id]; seen && current.BaseScore >= score.BaseScore {
					continue
				}
				out[id] = score
			}
		}
	}
	return out
}
