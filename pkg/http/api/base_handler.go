// Package api holds the HTTP plumbing shared by the API versions: the MIME
// types pinned by the Harbor contract, the JSON/gzip response writers and the
// TLS-terminating server.
package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const (
	HeaderContentType     = "Content-Type"
	HeaderContentEncoding = "Content-Encoding"
	HeaderAccept          = "Accept"
	HeaderAcceptEncoding  = "Accept-Encoding"
	// HeaderRefreshAfter is the report poll hint. Harbor parses it with
	// ParseInt(v, 10, 8), so the value MUST be <= 127.
	HeaderRefreshAfter = "Refresh-After"
)

// Error holds the information about an error, including metadata about its JSON
// structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

type MimeTypeParams map[string]string

var (
	MimeTypeVersion = MimeTypeParams{"version": "1.0"}

	MimeTypeOCIImageManifest = MIMEType{
		Type:    "application",
		Subtype: "vnd.oci.image.manifest.v1+json",
	}
	MimeTypeDockerImageManifestV2 = MIMEType{
		Type:    "application",
		Subtype: "vnd.docker.distribution.manifest.v2+json",
	}
	MimeTypeScanResponse = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.scan.response+json",
		Params:  MimeTypeVersion,
	}
	// MimeTypeSecurityVulnerabilityReport is the exact produces MIME type pinned
	// by the Harbor contract: "application/vnd.security.vulnerability.report;
	// version=1.1". The legacy native report type (version=1.0) is deliberately
	// not advertised: it carries no preferred_cvss and Harbor accepts 1.1.
	MimeTypeSecurityVulnerabilityReport = MIMEType{
		Type:    "application",
		Subtype: "vnd.security.vulnerability.report",
		Params:  MimeTypeParams{"version": "1.1"},
	}
	MimeTypeMetadata = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.metadata+json",
		Params:  MimeTypeVersion,
	}
	MimeTypeError = MIMEType{
		Type:    "application",
		Subtype: "vnd.scanner.adapter.error",
		Params:  MimeTypeVersion,
	}
)

// MIMEType represents a MIME type, as originally defined in RFC 2046 and
// subsequently used in other Internet protocols including HTTP.
type MIMEType struct {
	Type    string
	Subtype string
	Params  MimeTypeParams
}

func (mt MIMEType) MarshalJSON() ([]byte, error) {
	return json.Marshal(mt.String())
}

func (mt *MIMEType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return mt.Parse(s)
}

func (mt *MIMEType) String() string {
	if mt.Type == "" || mt.Subtype == "" {
		return ""
	}
	s := fmt.Sprintf("%s/%s", mt.Type, mt.Subtype)
	if len(mt.Params) == 0 {
		return s
	}
	params := make([]string, 0, len(mt.Params))
	for k, v := range mt.Params {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s; %s", s, strings.Join(params, ";"))
}

// Parse resolves the Accept header sent by Harbor for the report endpoint. This
// adapter produces only the generic vulnerability report, so it accepts that
// type (with or without the version parameter). Anything else is unsupported.
func (mt *MIMEType) Parse(value string) error {
	// No Accept, or a wildcard, means the client takes whatever we produce
	// (RFC 9110 section 12.5.1). There is exactly one report type, so that is it.
	if v := strings.TrimSpace(value); v == "" || v == "*/*" {
		*mt = MimeTypeSecurityVulnerabilityReport
		return nil
	}
	// mime.ParseMediaType rather than a string switch: the switch only matched
	// this adapter's own spelling, so a client sending the same type without the
	// space after ";" -- which RFC 9110 permits and other clients emit -- got a
	// 415 for a request it had every right to make.
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return fmt.Errorf("unsupported mime type: %s: %w", value, err)
	}

	want := fmt.Sprintf("%s/%s", MimeTypeSecurityVulnerabilityReport.Type, MimeTypeSecurityVulnerabilityReport.Subtype)
	if mediaType != want {
		return fmt.Errorf("unsupported mime type: %s", value)
	}
	// The version parameter is optional, but a version we do not produce is not
	// something to answer with a report anyway.
	if v, ok := params["version"]; ok && v != MimeTypeSecurityVulnerabilityReport.Params["version"] {
		return fmt.Errorf("unsupported mime type version: %s", value)
	}

	mt.Type = MimeTypeSecurityVulnerabilityReport.Type
	mt.Subtype = MimeTypeSecurityVulnerabilityReport.Subtype
	mt.Params = MimeTypeSecurityVulnerabilityReport.Params
	return nil
}

func (mt *MIMEType) Equal(other MIMEType) bool {
	if mt.Type != other.Type || mt.Subtype != other.Subtype || len(mt.Params) != len(other.Params) {
		return false
	}
	for k, v := range mt.Params {
		if other.Params[k] != v {
			return false
		}
	}
	return true
}

type BaseHandler struct{}

func (h *BaseHandler) WriteJSON(res http.ResponseWriter, data any, mimeType MIMEType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())
	res.WriteHeader(statusCode)

	if err := json.NewEncoder(res).Encode(data); err != nil {
		slog.Error("Error while writing JSON", slog.String("err", err.Error()))
		h.SendInternalServerError(res)
		return
	}
}

// WriteRawJSON writes a pre-marshaled JSON payload (json.RawMessage) with the
// given MIME type, gzip-encoding the body when the client accepts it. The report
// path must stream stored bytes rather than re-marshal per poll: Harbor's client
// has a 5s per-request timeout and polls the same report until the scan ends.
func (h *BaseHandler) WriteRawJSON(res http.ResponseWriter, req *http.Request, payload []byte, mimeType MIMEType, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType.String())

	if clientAcceptsGzip(req) {
		res.Header().Set(HeaderContentEncoding, "gzip")
		res.WriteHeader(statusCode)
		gz := gzip.NewWriter(res)
		if _, err := gz.Write(payload); err != nil {
			slog.Error("Error while writing gzip body", slog.String("err", err.Error()))
		}
		if err := gz.Close(); err != nil {
			slog.Error("Error while closing gzip writer", slog.String("err", err.Error()))
		}
		return
	}

	res.WriteHeader(statusCode)
	if _, err := res.Write(payload); err != nil {
		slog.Error("Error while writing body", slog.String("err", err.Error()))
	}
}

// clientAcceptsGzip honors the q-values in Accept-Encoding. A substring match
// treated "gzip;q=0" -- the explicit way to refuse an encoding -- as acceptance,
// so a client that said it could not decompress got a compressed report.
func clientAcceptsGzip(req *http.Request) bool {
	if req == nil {
		return false
	}

	wildcard := false
	for _, directive := range strings.Split(req.Header.Get(HeaderAcceptEncoding), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(directive), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "gzip" && name != "*" {
			continue
		}

		acceptable := true
		if _, q, found := strings.Cut(strings.ToLower(params), "q="); found {
			if weight, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err == nil {
				acceptable = weight > 0
			}
		}

		// An explicit "gzip" settles it either way; "*" only fills in when gzip
		// is not named at all.
		if name == "gzip" {
			return acceptable
		}
		wildcard = acceptable
	}
	return wildcard
}

func (h *BaseHandler) WriteJSONError(res http.ResponseWriter, err Error) {
	data := struct {
		Err Error `json:"error"`
	}{err}

	h.WriteJSON(res, data, MimeTypeError, err.HTTPCode)
}

func (h *BaseHandler) SendInternalServerError(res http.ResponseWriter) {
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}
