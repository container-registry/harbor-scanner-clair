package clair

import (
	"encoding/json"
	"time"
)

// Index report states, from claircore/indexer/controller/state.go. Only the two
// terminal ones matter here: the POST is synchronous, so the report the adapter
// gets back has already reached one of them.
const (
	StateIndexFinished = "IndexFinished"
	StateIndexError    = "IndexError"
)

// Manifest is the indexer request body. Clair fetches every layer itself, which
// is why the adapter sends URIs and headers rather than bytes.
type Manifest struct {
	Hash   string  `json:"hash"`
	Layers []Layer `json:"layers"`
}

// Layer headers are map[string][]string on the wire, not map[string]string.
//
// media_type is accepted by Clair's schema but discarded: libindex converts via
// internal/wart.LayersToDescriptions, which hardcodes
// application/vnd.oci.image.layer.v1.tar and sniffs the real compression from
// the fetched bytes. So it is deliberately not sent.
type Layer struct {
	Hash    string              `json:"hash"`
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// IndexReport decodes only the four fields the adapter branches on. packages,
// distributions, repository and environments are ignored on this path: the
// vulnerability report carries everything the transformer needs.
type IndexReport struct {
	ManifestHash string `json:"manifest_hash"`
	State        string `json:"state"`
	Success      bool   `json:"success"`
	Err          string `json:"err"`
}

// VulnerabilityReport is likewise partial. distributions, environments and
// repository are not decoded, because the transformer reads the distribution
// from the vulnerability's own distribution field.
type VulnerabilityReport struct {
	ManifestHash           string                       `json:"manifest_hash"`
	Packages               map[string]*Package          `json:"packages"`
	Vulnerabilities        map[string]*Vulnerability    `json:"vulnerabilities"`
	PackageVulnerabilities map[string][]string          `json:"package_vulnerabilities"`
	Enrichments            map[string][]json.RawMessage `json:"enrichments"`
}

type Package struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Module  string `json:"module,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

type Distribution struct {
	ID         string `json:"id"`
	DID        string `json:"did"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

// Vulnerability is one finding.
//
// Links is a SPACE-SEPARATED list of URIs, not an array. NormalizedSeverity is
// one of Unknown|Negligible|Low|Medium|High|Critical, which is exactly Harbor's
// set. The distribution's JSON tag is "distribution"; the example in upstream's
// openapi.yaml says "dist" and is stale, the struct tags are what is on the wire.
type Vulnerability struct {
	ID                 string        `json:"id"`
	Updater            string        `json:"updater"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Links              string        `json:"links"`
	Severity           string        `json:"severity"`
	NormalizedSeverity string        `json:"normalized_severity"`
	FixedInVersion     string        `json:"fixed_in_version"`
	Dist               *Distribution `json:"distribution,omitempty"`
}

// updateOperation is one entry of the matcher's internal update_operation
// listing, used only for the vulnerability-database timestamp.
type updateOperation struct {
	Ref     string    `json:"ref"`
	Updater string    `json:"updater"`
	Date    time.Time `json:"date"`
	Kind    string    `json:"kind"`
}
