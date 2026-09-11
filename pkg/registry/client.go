// Package registry fetches an artifact's manifest from the registry Harbor
// named in the scan request, and turns it into the manifest Clair's indexer
// wants.
//
// The authorization Harbor mints for a scan is a pull-scoped registry token
// with a limited lifetime. It is used here to read the manifest and is then
// forwarded verbatim as the header Clair fetches every blob with, which is the
// whole of the adapter's registry credential handling: no token exchange, no
// registry login, no second credential to configure.
package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

// Manifest media types the adapter accepts. They are the two it advertises in
// /api/v1/metadata as consumable, so anything else here means Harbor sent an
// artifact it was told not to send.
const (
	mediaTypeDockerManifestV2 = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeOCIManifest      = "application/vnd.oci.image.manifest.v1+json"
)

// Index media types, recognized only to reject them with a message that says
// what went wrong.
const (
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
)

// maxManifestBytes bounds the manifest body. A manifest is a list of layer
// descriptors; a megabyte of them is already implausible, and the limit keeps a
// hostile or broken registry from being able to exhaust the adapter's memory.
const maxManifestBytes = 4 << 20

// maxErrorBytes bounds how much of a failed response is copied into the error
// message, which ends up in Harbor's scan job failure detail.
const maxErrorBytes = 512

// scannableLayerMediaTypes is what Clair's fetcher can actually read: tar,
// optionally gzip or zstd compressed.
//
// The foreign/nondistributable types are deliberately absent, unlike the
// equivalent list in the trivy adapter. Their blobs are by definition not in
// this registry, so {registry}/v2/{repo}/blobs/{digest} 404s and Clair fails the
// whole index with an opaque fetch error. Rejecting them here turns a Windows
// base image into a clear [unscannable_layer] message instead.
var scannableLayerMediaTypes = map[string]struct{}{
	"application/vnd.docker.image.rootfs.diff.tar.gzip": {},
	"application/vnd.docker.image.rootfs.diff.tar":      {},
	"application/vnd.oci.image.layer.v1.tar":            {},
	"application/vnd.oci.image.layer.v1.tar+gzip":       {},
	"application/vnd.oci.image.layer.v1.tar+zstd":       {},
}

// Sentinel errors. The scan path branches on these with errors.Is to pick the
// category it reports to Harbor, so they are part of this package's contract.
var (
	// ErrRegistryAuth means the registry rejected the authorization Harbor
	// minted for this scan.
	ErrRegistryAuth = errors.New("the registry rejected the scan authorization")
	// ErrManifestNotFound means the registry has no manifest under that digest.
	ErrManifestNotFound = errors.New("the registry has no manifest for the artifact")
	// ErrManifestFetch is any other unusable response from the registry.
	ErrManifestFetch = errors.New("fetching the artifact manifest failed")
	// ErrUnsupportedArtifact means the response is not a single image manifest
	// Clair can index: an index, a foreign media type, no layers, or a digest
	// outside Clair's sha256-only schema.
	ErrUnsupportedArtifact = errors.New("the artifact is not a scannable image manifest")
	// ErrUnscannableLayer means a layer is not a filesystem tarball.
	ErrUnscannableLayer = errors.New("the artifact has a layer clair cannot index")
)

// Config is the registry connection. The trust configuration is passed
// separately, as the *tls.Config the whole adapter dials out with.
type Config struct {
	// RequestTimeout bounds one manifest GET.
	RequestTimeout time.Duration
}

// defaultRequestTimeout applies to a Config left zero.
const defaultRequestTimeout = 30 * time.Second

// Manifest is the part of a Docker schema 2 or OCI image manifest the adapter
// reads. The two are structurally identical here, so one struct decodes both.
//
// The config descriptor is deliberately not modeled. The v1 adapter iterated
// every reference and skipped the config blob by media type, a check that
// missed the OCI config type entirely; reading layers directly never sees it.
type Manifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Layers        []ocispec.Descriptor `json:"layers"`
	// Manifests is non-empty only on an index or manifest list.
	Manifests []ocispec.Descriptor `json:"manifests"`
}

// Client reads manifests from the registry. It holds one http.Client for the
// process: the transport's connection pool is the point, and the v1 adapter's
// package-level sync.Once singleton made the TLS configuration of the first
// caller permanent for every later one.
type Client struct {
	http           *http.Client
	requestTimeout time.Duration
}

// NewClient builds the registry client. tlsConfig is the adapter's outbound
// trust configuration and may be nil.
func NewClient(cfg Config, tlsConfig *tls.Config) *Client {
	// A cloned DefaultTransport keeps the connection pooling and proxy support
	// a bare &http.Transport{} silently drops.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	return &Client{
		// Timeout stays unset; each call sets its own context deadline, so the
		// bound is visible to the caller's cancellation too.
		http:           &http.Client{Transport: transport},
		requestTimeout: timeout,
	}
}

// GetManifest fetches and validates the manifest for the artifact in req.
func (c *Client) GetManifest(ctx context.Context, req harbor.ScanRequest) (*Manifest, error) {
	url := manifestURL(req)

	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building the request for %s: %w", ErrManifestFetch, url, err)
	}
	httpReq.Header.Set("Accept", mediaTypeOCIManifest+", "+mediaTypeDockerManifestV2)
	// Forwarded byte-identical, and only when Harbor sent one: a public project
	// pulled anonymously has no authorization, and an empty header value is not
	// the same request as no header at all.
	if req.Registry.Authorization != "" {
		httpReq.Header.Set("Authorization", req.Registry.Authorization)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		// Not wrapped in a sentinel: a transport failure or an expired deadline
		// must stay recognizable as such, so the scan path reports it as a
		// network or timeout problem rather than as a bad manifest.
		return nil, fmt.Errorf("getting %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("reading the manifest from %s: %w", url, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w (%s) for %s: %s", ErrRegistryAuth, resp.Status, url, snippet(body))
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s: %s", ErrManifestNotFound, url, snippet(body))
	default:
		return nil, fmt.Errorf("%w: %s answered %s: %s", ErrManifestFetch, url, resp.Status, snippet(body))
	}

	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("%w: decoding the manifest from %s: %w", ErrManifestFetch, url, err)
	}
	if err := manifest.validate(resp.Header.Get("Content-Type")); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// validate rejects everything Clair would fail on later, or worse, index into a
// useless report. contentType is the response header, used as the media type
// when the body omits its own, which an OCI image manifest is allowed to do.
func (m *Manifest) validate(contentType string) error {
	mediaType := m.MediaType
	if mediaType == "" {
		mediaType = parseMediaType(contentType)
	}

	// Harbor fans an index out to its child manifests itself and never sends
	// the index, precisely because the adapter does not advertise index media
	// types. One arriving here means the scanner registration in Harbor does
	// not match this adapter's metadata.
	if len(m.Manifests) > 0 || mediaType == mediaTypeOCIIndex || mediaType == mediaTypeDockerManifestList {
		return fmt.Errorf("%w: %s is an image index; harbor is expected to scan its child manifests individually",
			ErrUnsupportedArtifact, mediaTypeOrUnknown(mediaType))
	}
	if mediaType != "" && mediaType != mediaTypeOCIManifest && mediaType != mediaTypeDockerManifestV2 {
		return fmt.Errorf("%w: unsupported manifest media type %q", ErrUnsupportedArtifact, mediaType)
	}
	// Clair rejects a manifest with no layers with a 400, which reaches the
	// operator as an opaque bad-request error.
	if len(m.Layers) == 0 {
		return fmt.Errorf("%w: the manifest has no layers", ErrUnsupportedArtifact)
	}

	for _, layer := range m.Layers {
		if _, ok := scannableLayerMediaTypes[layer.MediaType]; !ok {
			return fmt.Errorf("%w: layer %s has media type %q, which is not a filesystem tarball",
				ErrUnscannableLayer, layer.Digest, layer.MediaType)
		}
		// Clair's manifest schema is ^sha256:[a-f0-9]{64}$, so anything else is
		// rejected before it costs an index call.
		if err := layer.Digest.Validate(); err != nil {
			return fmt.Errorf("%w: layer digest %q is not a valid digest: %w", ErrUnsupportedArtifact, layer.Digest, err)
		}
		if layer.Digest.Algorithm() != digest.SHA256 {
			return fmt.Errorf("%w: layer digest %q is not sha256, which is the only algorithm clair accepts",
				ErrUnsupportedArtifact, layer.Digest)
		}
	}
	return nil
}

// ClairManifest describes the artifact the way Clair's indexer wants it: the
// artifact digest as the manifest hash, one entry per layer in manifest order,
// and the token Harbor minted for this scan forwarded as the header Clair
// fetches each blob with.
func (m *Manifest) ClairManifest(req harbor.ScanRequest) clair.Manifest {
	manifest := clair.Manifest{
		// Clair's spec: this SHOULD be the OCI image manifest's digest, but it
		// is not enforced. Harbor's digest is used so the vulnerability report
		// can be fetched under the value the scan request named.
		Hash:   req.Artifact.Digest,
		Layers: make([]clair.Layer, 0, len(m.Layers)),
	}
	base := strings.TrimRight(req.Registry.URL, "/")

	for _, layer := range m.Layers {
		// The compressed blob digest from the descriptor, never a diff_id:
		// Clair verifies the digest against the bytes as they arrive on the
		// wire, before decompression.
		hash := layer.Digest.String()
		clairLayer := clair.Layer{
			Hash: hash,
			URI:  fmt.Sprintf("%s/v2/%s/blobs/%s", base, req.Artifact.Repository, hash),
		}
		if req.Registry.Authorization != "" {
			// Authorization and nothing else. No Connection: close, which is a
			// hop-by-hop header Go's transport manages and which cost the v1
			// adapter a fresh connection per layer; and no Accept, because
			// Clair sniffs the compression from the body and auto-corrects an
			// empty or octet-stream content type, which is exactly what a
			// registry and an S3 redirect target serve.
			clairLayer.Headers = map[string][]string{"Authorization": {req.Registry.Authorization}}
		}
		manifest.Layers = append(manifest.Layers, clairLayer)
	}
	return manifest
}

func manifestURL(req harbor.ScanRequest) string {
	return fmt.Sprintf("%s/v2/%s/manifests/%s",
		strings.TrimRight(req.Registry.URL, "/"), req.Artifact.Repository, req.Artifact.Digest)
}

func parseMediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	parsed, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return parsed
}

func mediaTypeOrUnknown(mediaType string) string {
	if mediaType == "" {
		return "the artifact"
	}
	return mediaType
}

func snippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > maxErrorBytes {
		return text[:maxErrorBytes] + "..."
	}
	return text
}
