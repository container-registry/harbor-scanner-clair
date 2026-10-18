package scan

import (
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

// noFixSentinel is what Clair puts in fixed_in_version when a vulnerability has
// no fix. Harbor renders the value verbatim, so "0" must not reach it.
const noFixSentinel = "0"

type systemClock struct{}

func (c *systemClock) Now() time.Time {
	return time.Now()
}

// Transformer maps between the Harbor and Clair wire models. The scanner
// metadata is passed in rather than read from the environment so the value
// Harbor sees in a report is the one it saw in /api/v1/metadata.
//
// This is the transitional shape that keeps the scan path working on Clair v4;
// CVSS, vendor attributes and dedup arrive with the report transformer.
type Transformer struct {
	clock interface {
		Now() time.Time
	}
}

func NewTransformer() *Transformer {
	return &Transformer{
		clock: &systemClock{},
	}
}

func (t *Transformer) ToHarborScanReport(scanner harbor.Scanner, artifact harbor.Artifact, source *clair.VulnerabilityReport) harbor.ScanReport {
	items := t.toVulnerabilityItems(source)
	return harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Scanner:         scanner,
		Artifact:        artifact,
		Severity:        rollUpSeverity(items),
		Vulnerabilities: items,
	}
}

// toVulnerabilityItems walks package_vulnerabilities, which is the only edge in
// the report that ties a finding to the package it was found in.
func (t *Transformer) toVulnerabilityItems(report *clair.VulnerabilityReport) []harbor.VulnerabilityItem {
	items := make([]harbor.VulnerabilityItem, 0)
	if report == nil {
		return items
	}

	for packageID, vulnerabilityIDs := range report.PackageVulnerabilities {
		pkg, ok := report.Packages[packageID]
		if !ok || pkg == nil {
			slog.Warn("Clair reported a vulnerability for an unknown package",
				slog.String("package_id", packageID))
			continue
		}
		for _, vulnerabilityID := range vulnerabilityIDs {
			vulnerability, ok := report.Vulnerabilities[vulnerabilityID]
			if !ok || vulnerability == nil {
				continue
			}
			items = append(items, harbor.VulnerabilityItem{
				ID:          vulnerability.Name,
				Pkg:         pkg.Name,
				Version:     pkg.Version,
				FixVersion:  fixVersion(vulnerability.FixedInVersion),
				Severity:    toHarborSeverity(vulnerability.NormalizedSeverity),
				Description: vulnerability.Description,
				// links is a space-separated string on the wire, not an array.
				Links: strings.Fields(vulnerability.Links),
			})
		}
	}

	// Report order would otherwise follow Go's map iteration, which changes
	// between runs of the same scan.
	slices.SortFunc(items, func(a, b harbor.VulnerabilityItem) int {
		return strings.Compare(a.Pkg+"\x00"+a.Version+"\x00"+a.ID, b.Pkg+"\x00"+b.Version+"\x00"+b.ID)
	})
	return items
}

func fixVersion(fixedInVersion string) string {
	if fixedInVersion == noFixSentinel {
		return ""
	}
	return fixedInVersion
}

func rollUpSeverity(items []harbor.VulnerabilityItem) harbor.Severity {
	overall := harbor.SevNone
	for _, item := range items {
		if item.Severity > overall {
			overall = item.Severity
		}
	}
	return overall
}

// toHarborSeverity maps Clair's normalized_severity onto Harbor's severity.
// The two vocabularies are identical, so this is an identity mapping rather
// than a translation; anything outside it means Clair changed its set.
func toHarborSeverity(normalized string) harbor.Severity {
	switch normalized {
	case "Negligible":
		return harbor.SevNegligible
	case "Low":
		return harbor.SevLow
	case "Medium":
		return harbor.SevMedium
	case "High":
		return harbor.SevHigh
	case "Critical":
		return harbor.SevCritical
	case "Unknown", "":
		return harbor.SevUnknown
	default:
		slog.Warn("Unknown Clair severity", slog.String("normalized_severity", normalized))
		return harbor.SevUnknown
	}
}
