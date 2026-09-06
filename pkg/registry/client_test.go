package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

const (
	testRepository = "library/alpine"
	testDigest     = "sha256:e7b300aee9f9bf3433d32bc9305bfdd22183beb59d933b48d77ab56ba53a197a"
	testAuth       = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.harbor.minted"
	// alpine:3.10's single layer, from testdata/manifest_schema2.json.
	alpineLayerDigest = "sha256:396c31837116ac290458afcb928f68b6cc1c7bdd6963fc72f52f365a2a89c1b5"
)

// fixture serves one testdata manifest and records the request the client made.
type fixture struct {
	server *httptest.Server
	client *Client

	requestPath   string
	requestAccept string
	requestAuth   string
	authSent      bool
}

func newFixture(t *testing.T, status int, contentType string, body []byte) *fixture {
	t.Helper()
	f := &fixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		f.requestPath = req.URL.Path
		f.requestAccept = req.Header.Get("Accept")
		f.requestAuth = req.Header.Get("Authorization")
		_, f.authSent = req.Header["Authorization"]

		if contentType != "" {
			res.Header().Set("Content-Type", contentType)
		}
		res.WriteHeader(status)
		_, _ = res.Write(body)
	}))
	t.Cleanup(f.server.Close)

	f.client = NewClient(Config{RequestTimeout: 5 * time.Second}, nil)
	return f
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return body
}

func scanRequest(registryURL string) harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: registryURL, Authorization: testAuth},
		Artifact: harbor.Artifact{Repository: testRepository, Digest: testDigest},
	}
}

func TestClient_GetManifest(t *testing.T) {
	t.Run("Should request the manifest by digest and forward the scan authorization", func(t *testing.T) {
		f := newFixture(t, http.StatusOK, mediaTypeDockerManifestV2, testdata(t, "manifest_schema2.json"))

		manifest, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
		require.NoError(t, err)

		assert.Equal(t, "/v2/"+testRepository+"/manifests/"+testDigest, f.requestPath)
		assert.Equal(t,
			"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
			f.requestAccept)
		assert.Equal(t, testAuth, f.requestAuth, "the token Harbor minted must be forwarded byte-identical")
		require.Len(t, manifest.Layers, 1)
		assert.Equal(t, alpineLayerDigest, manifest.Layers[0].Digest.String())
	})

	// A trailing slash on registry.url is what Harbor sends for some
	// registrations, and doubling the slash makes the registry 404.
	t.Run("Should not double the slash when the registry URL ends in one", func(t *testing.T) {
		f := newFixture(t, http.StatusOK, mediaTypeDockerManifestV2, testdata(t, "manifest_schema2.json"))

		req := scanRequest(f.server.URL + "/")
		_, err := f.client.GetManifest(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "/v2/"+testRepository+"/manifests/"+testDigest, f.requestPath)
	})

	// A public project is pulled anonymously, and an empty header value is not
	// the same request as no header at all.
	t.Run("Should send no Authorization header when the scan request carries none", func(t *testing.T) {
		f := newFixture(t, http.StatusOK, mediaTypeDockerManifestV2, testdata(t, "manifest_schema2.json"))

		req := scanRequest(f.server.URL)
		req.Registry.Authorization = ""
		_, err := f.client.GetManifest(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, f.authSent)
	})

	// An OCI manifest may omit mediaType from the body, so the response header
	// is what identifies it.
	t.Run("Should accept an OCI manifest whose media type comes from the response header", func(t *testing.T) {
		body := testdata(t, "manifest_oci.json")
		f := newFixture(t, http.StatusOK, mediaTypeOCIManifest+"; charset=utf-8", body)

		manifest, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
		require.NoError(t, err)
		assert.Len(t, manifest.Layers, 2)
	})

	t.Run("Should map registry status codes onto sentinel errors", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			status   int
			expected error
		}{
			{"401", http.StatusUnauthorized, ErrRegistryAuth},
			{"403", http.StatusForbidden, ErrRegistryAuth},
			{"404", http.StatusNotFound, ErrManifestNotFound},
			{"500", http.StatusInternalServerError, ErrManifestFetch},
			{"502", http.StatusBadGateway, ErrManifestFetch},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, tc.status, "application/json", []byte(`{"errors":[{"code":"DENIED"}]}`))

				_, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expected)
			})
		}
	})

	t.Run("Should reject an artifact clair cannot index", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			contentType string
			body        []byte
			expected    error
			message     string
		}{
			{
				name:        "an image index",
				contentType: mediaTypeOCIIndex,
				body:        testdata(t, "manifest_index.json"),
				expected:    ErrUnsupportedArtifact,
				message:     "image index",
			},
			{
				name:        "a cosign signature",
				contentType: mediaTypeOCIManifest,
				body:        testdata(t, "manifest_cosign.json"),
				expected:    ErrUnscannableLayer,
				message:     "application/vnd.dev.cosign.simplesigning.v1+json",
			},
			{
				name:        "no layers",
				contentType: mediaTypeOCIManifest,
				body:        []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`),
				expected:    ErrUnsupportedArtifact,
				message:     "no layers",
			},
			{
				name:        "a non-sha256 layer digest",
				contentType: mediaTypeOCIManifest,
				body: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` +
					`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":1,` +
					`"digest":"sha512:0f5f1b1d2b8ae4d4b1ee1ee62a52ffb3f7f5a0d5a5a2e5f7bcbb0a0dd3f6d4b10f5f1b1d2b8ae4d4b1ee1ee62a52ffb3f7f5a0d5a5a2e5f7bcbb0a0dd3f6d4b1"}]}`),
				expected: ErrUnsupportedArtifact,
				message:  "not sha256",
			},
			{
				name:        "a foreign layer",
				contentType: mediaTypeDockerManifestV2,
				body: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","layers":[` +
					`{"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","size":1,` +
					`"digest":"` + alpineLayerDigest + `"}]}`),
				expected: ErrUnscannableLayer,
				message:  "foreign",
			},
			{
				name:        "an unrelated manifest media type",
				contentType: "application/vnd.cncf.helm.config.v1+json",
				body:        []byte(`{"schemaVersion":2,"mediaType":"application/vnd.cncf.helm.config.v1+json","layers":[]}`),
				expected:    ErrUnsupportedArtifact,
				message:     "unsupported manifest media type",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, http.StatusOK, tc.contentType, tc.body)

				_, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expected)
				assert.Contains(t, err.Error(), tc.message)
			})
		}
	})

	t.Run("Should reject an undecodable body", func(t *testing.T) {
		f := newFixture(t, http.StatusOK, mediaTypeOCIManifest, []byte("<html>proxy error</html>"))

		_, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestFetch)
	})

	// A transport failure must not be reported as a bad manifest: the scan path
	// categorizes it as a network problem, which points at a different fix.
	t.Run("Should not wrap a transport failure in a manifest sentinel", func(t *testing.T) {
		f := newFixture(t, http.StatusOK, mediaTypeOCIManifest, nil)
		f.server.Close()

		_, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrManifestFetch)
		assert.NotErrorIs(t, err, ErrUnsupportedArtifact)
	})
}

func TestManifest_ClairManifest(t *testing.T) {
	f := newFixture(t, http.StatusOK, mediaTypeOCIManifest, testdata(t, "manifest_oci.json"))

	req := scanRequest("https://harbor.example.com/")
	manifest, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
	require.NoError(t, err)

	clairManifest := manifest.ClairManifest(req)

	assert.Equal(t, clair.Manifest{
		// The artifact digest, not anything derived from the layers.
		Hash: testDigest,
		Layers: []clair.Layer{
			{
				Hash:    "sha256:31e352740f534f9ad170f75378a84fe453d6156e40700b882d737a8f4a6988a3",
				URI:     "https://harbor.example.com/v2/library/alpine/blobs/sha256:31e352740f534f9ad170f75378a84fe453d6156e40700b882d737a8f4a6988a3",
				Headers: map[string][]string{"Authorization": {testAuth}},
			},
			{
				Hash:    "sha256:5a0b6a8e9d9a1de4e2f5a3a6bbfa2df0b6a2ec7b9e9f0d3c1b2a4d5e6f708192",
				URI:     "https://harbor.example.com/v2/library/alpine/blobs/sha256:5a0b6a8e9d9a1de4e2f5a3a6bbfa2df0b6a2ec7b9e9f0d3c1b2a4d5e6f708192",
				Headers: map[string][]string{"Authorization": {testAuth}},
			},
		},
	}, clairManifest, "layers keep manifest order, and Authorization is the only header")

	for _, layer := range clairManifest.Layers {
		assert.NotContains(t, layer.Headers, "Accept")
		assert.NotContains(t, layer.Headers, "Connection")
	}
}

func TestManifest_ClairManifestWithoutAuthorization(t *testing.T) {
	manifest := &Manifest{Layers: testdataLayers(t)}

	req := scanRequest("https://harbor.example.com")
	req.Registry.Authorization = ""

	clairManifest := manifest.ClairManifest(req)
	require.Len(t, clairManifest.Layers, 1)
	assert.Nil(t, clairManifest.Layers[0].Headers, "an anonymous pull sends no header rather than an empty one")
}

func testdataLayers(t *testing.T) []ocispec.Descriptor {
	t.Helper()
	f := newFixture(t, http.StatusOK, mediaTypeDockerManifestV2, testdata(t, "manifest_schema2.json"))
	manifest, err := f.client.GetManifest(context.Background(), scanRequest(f.server.URL))
	require.NoError(t, err)
	return manifest.Layers
}
