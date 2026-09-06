package scan

import (
	"cmp"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

// Clock wraps Now. It is injected so a test can pin generated_at and keep the
// golden reports byte-stable.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (c *systemClock) Now() time.Time {
	return time.Now()
}

// Transformer maps between the Harbor and Clair wire models. The scanner
// metadata is passed in rather than read from the environment so the value
// Harbor sees in a report is the one it saw in /api/v1/metadata.
type Transformer struct {
	clock Clock
}

func NewTransformer() *Transformer {
	return &Transformer{
		clock: &systemClock{},
	}
}

// Transform maps a Clair v4 vulnerability report onto the Harbor scan report.
func (t *Transformer) Transform(artifact harbor.Artifact, scanner harbor.Scanner, report *clair.VulnerabilityReport) harbor.ScanReport {
	items := t.toVulnerabilityItems(report)
	return harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Artifact:        artifact,
		Scanner:         scanner,
		Severity:        toHighestSeverity(items),
		Vulnerabilities: items,
	}
}

// dedupKey is Harbor's notion of a distinct finding. Clair reports one
// vulnerability once per package id, and the same package can be indexed under
// several ids, so the name and version are what separate two rows.
type dedupKey struct {
	pkg     string
	version string
	id      string
}

// candidate carries the Clair vulnerability id alongside the mapped item, as
// the last dedup tie-break is on that id and it is not part of the item.
type candidate struct {
	item   harbor.VulnerabilityItem
	vulnID string
}

func (t *Transformer) toVulnerabilityItems(report *clair.VulnerabilityReport) []harbor.VulnerabilityItem {
	if report == nil {
		return []harbor.VulnerabilityItem{}
	}

	cvssByID := report.CVSSByVulnID()
	surviving := make(map[dedupKey]candidate, len(report.PackageVulnerabilities))

	var danglingPackages, danglingVulnerabilities int
	unknownSeverities := make(map[string]struct{})

	// The maps are walked through sorted keys so that map order never decides
	// which of two equally ranked candidates survives the dedup.
	for _, pkgID := range slices.Sorted(maps.Keys(report.PackageVulnerabilities)) {
		pkg := report.Packages[pkgID]
		if pkg == nil {
			danglingPackages++
			continue
		}
		for _, vulnID := range slices.Sorted(slices.Values(report.PackageVulnerabilities[pkgID])) {
			vuln := report.Vulnerabilities[vulnID]
			if vuln == nil {
				danglingVulnerabilities++
				continue
			}
			if _, known := clairToHarborSeverity[vuln.NormalizedSeverity]; !known {
				unknownSeverities[vuln.NormalizedSeverity] = struct{}{}
			}

			cvss, hasCVSS := cvssByID[vulnID]
			next := candidate{
				item:   toVulnerabilityItem(pkg, vuln, vulnID, cvss, hasCVSS),
				vulnID: vulnID,
			}
			key := dedupKey{pkg: pkg.Name, version: pkg.Version, id: next.item.ID}
			if current, seen := surviving[key]; !seen || outranks(next, current) {
				surviving[key] = next
			}
		}
	}

	// One warning per report, not per finding: a broken report is broken for
	// hundreds of packages at once and the log is what an operator reads.
	if danglingPackages > 0 || danglingVulnerabilities > 0 {
		slog.Warn("Clair report references entries it does not carry; those findings are dropped",
			slog.String("manifest_hash", report.ManifestHash),
			slog.Int("missing_packages", danglingPackages),
			slog.Int("missing_vulnerabilities", danglingVulnerabilities))
	}
	if len(unknownSeverities) > 0 {
		slog.Warn("Unrecognized Clair normalized severity, reported as Unknown",
			slog.String("manifest_hash", report.ManifestHash),
			slog.String("severities", strings.Join(slices.Sorted(maps.Keys(unknownSeverities)), ", ")))
	}

	items := make([]harbor.VulnerabilityItem, 0, len(surviving))
	for _, c := range surviving {
		items = append(items, c.item)
	}
	slices.SortFunc(items, func(a, b harbor.VulnerabilityItem) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.Pkg, b.Pkg),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.ID, b.ID),
		)
	})
	return items
}

func toVulnerabilityItem(pkg *clair.Package, vuln *clair.Vulnerability, vulnID string, cvss clair.CVSS, hasCVSS bool) harbor.VulnerabilityItem {
	id := vuln.Name
	if id == "" {
		id = vulnID
	}

	item := harbor.VulnerabilityItem{
		ID:               id,
		Pkg:              pkg.Name,
		Version:          pkg.Version,
		FixVersion:       toFixVersion(vuln.FixedInVersion),
		Severity:         toSeverity(vuln.NormalizedSeverity, cvss, hasCVSS),
		Description:      vuln.Description,
		Links:            toLinks(vuln.Links),
		VendorAttributes: toVendorAttributes(vuln, cvss, hasCVSS),
	}
	if hasCVSS {
		// ScoreV2 and VectorV2 stay unset: the enricher collects Primary 3.1 and
		// 3.0 metrics only, so a v2 score never reaches the adapter.
		score := float32(cvss.BaseScore)
		item.PreferredCVSS = &harbor.CVSSDetails{
			ScoreV3:  &score,
			VectorV3: cvss.VectorString,
		}
	}
	return item
}

// toFixVersion drops Clair's no-fix sentinel. Quay writes "0" where a
// vulnerability has no fixed version, and omitempty then drops the field.
func toFixVersion(fixedInVersion string) string {
	if fixedInVersion == "0" {
		return ""
	}
	return fixedInVersion
}

// toLinks splits Clair's links, which are one space-separated string rather
// than an array. The result is never nil: json.Marshal writes a nil slice as
// null and Harbor's schema wants an array.
func toLinks(links string) []string {
	if fields := strings.Fields(links); len(fields) > 0 {
		return fields
	}
	return []string{}
}

var clairToHarborSeverity = map[string]harbor.Severity{
	"Unknown":    harbor.SevUnknown,
	"Negligible": harbor.SevNegligible,
	"Low":        harbor.SevLow,
	"Medium":     harbor.SevMedium,
	"High":       harbor.SevHigh,
	"Critical":   harbor.SevCritical,
}

// toSeverity is the identity on Clair's normalized set, with one fallback:
// Alpine content normalizes to Unknown even for a CVE that carries a score, so
// an Unknown with an enrichment takes its severity from the CVSS base score.
// The >= 9 boundary is deliberate; Quay's own 9 < score < 10 loses exactly 10.0.
func toSeverity(normalized string, cvss clair.CVSS, hasCVSS bool) harbor.Severity {
	severity, known := clairToHarborSeverity[normalized]
	if !known {
		severity = harbor.SevUnknown
	}
	if severity != harbor.SevUnknown || !hasCVSS {
		return severity
	}

	switch score := cvss.BaseScore; {
	case score >= 9:
		return harbor.SevCritical
	case score >= 7:
		return harbor.SevHigh
	case score >= 4:
		return harbor.SevMedium
	case score > 0:
		return harbor.SevLow
	default:
		return harbor.SevUnknown
	}
}

// cvssInfo keeps trivy's vendor_attributes shape so Harbor renders a score from
// this adapter exactly as it renders one from the Trivy adapter.
type cvssInfo struct {
	V3Score  *float32 `json:"V3Score,omitempty"`
	V3Vector string   `json:"V3Vector,omitempty"`
}

func toVendorAttributes(vuln *clair.Vulnerability, cvss clair.CVSS, hasCVSS bool) map[string]any {
	attributes := make(map[string]any, 2)
	if hasCVSS {
		score := float32(cvss.BaseScore)
		attributes["CVSS"] = map[string]cvssInfo{
			"nvd": {V3Score: &score, V3Vector: cvss.VectorString},
		}
	}

	// The raw distro severity is kept next to the normalized one: they disagree
	// often enough that an operator comparing Harbor against the distro's own
	// advisory needs to see both.
	clairAttributes := make(map[string]string, 3)
	if vuln.Updater != "" {
		clairAttributes["updater"] = vuln.Updater
	}
	if vuln.Severity != "" {
		clairAttributes["vendor_severity"] = vuln.Severity
	}
	if distribution := toDistributionName(vuln.Dist); distribution != "" {
		clairAttributes["distribution"] = distribution
	}
	if len(clairAttributes) > 0 {
		attributes["clair"] = clairAttributes
	}

	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func toDistributionName(dist *clair.Distribution) string {
	if dist == nil {
		return ""
	}
	if dist.PrettyName != "" {
		return dist.PrettyName
	}
	return strings.TrimSpace(dist.Name + " " + dist.Version)
}

// outranks decides which of two findings that share a dedup key survives:
// higher severity, then the higher CVSS score, then the smaller Clair
// vulnerability id.
func outranks(next, current candidate) bool {
	if next.item.Severity != current.item.Severity {
		return next.item.Severity > current.item.Severity
	}
	if nextScore, currentScore := scoreOf(next.item), scoreOf(current.item); nextScore != currentScore {
		return nextScore > currentScore
	}
	return next.vulnID < current.vulnID
}

func scoreOf(item harbor.VulnerabilityItem) float32 {
	if item.PreferredCVSS == nil || item.PreferredCVSS.ScoreV3 == nil {
		return 0
	}
	return *item.PreferredCVSS.ScoreV3
}

// toHighestSeverity rolls the report up. An empty report is None, not the zero
// value, which would marshal as an empty string and fail Harbor's parsing.
func toHighestSeverity(items []harbor.VulnerabilityItem) harbor.Severity {
	highest := harbor.SevNone
	for _, item := range items {
		if item.Severity > highest {
			highest = item.Severity
		}
	}
	return highest
}
