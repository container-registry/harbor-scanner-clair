package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
	"github.com/container-registry/harbor-scanner-clair/pkg/registry"
)

const (
	testJobID      = "job-1"
	layerDigestA   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	layerDigestB   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	artifactDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	testAuthValue  = "Bearer harbor-minted-token"
)

type fakeRegistry struct {
	manifest *registry.Manifest
	err      error

	request harbor.ScanRequest
	calls   int
}

func (r *fakeRegistry) GetManifest(_ context.Context, req harbor.ScanRequest) (*registry.Manifest, error) {
	r.calls++
	r.request = req
	if r.err != nil {
		return nil, r.err
	}
	return r.manifest, nil
}

type fakeClair struct {
	indexReport *clair.IndexReport
	indexErr    error
	report      *clair.VulnerabilityReport
	reportErr   error
	// onReport runs at the top of the report call, which is where a per-job
	// deadline realistically fires.
	onReport func()

	indexed       clair.Manifest
	reportedHash  string
	indexCalls    int
	reportedCalls int
}

func (c *fakeClair) Index(_ context.Context, m clair.Manifest) (*clair.IndexReport, error) {
	c.indexCalls++
	c.indexed = m
	if c.indexErr != nil {
		return nil, c.indexErr
	}
	return c.indexReport, nil
}

func (c *fakeClair) VulnerabilityReport(_ context.Context, manifestHash string) (*clair.VulnerabilityReport, error) {
	if c.onReport != nil {
		c.onReport()
	}
	c.reportedCalls++
	c.reportedHash = manifestHash
	if c.reportErr != nil {
		return nil, c.reportErr
	}
	return c.report, nil
}

func testManifest() *registry.Manifest {
	return &registry.Manifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Layers: []ocispec.Descriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerDigestA},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerDigestB},
		},
	}
}

func testScanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example.com", Authorization: testAuthValue},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: artifactDigest},
	}
}

func finishedIndexReport() *clair.IndexReport {
	return &clair.IndexReport{ManifestHash: artifactDigest, State: clair.StateIndexFinished, Success: true}
}

// newController wires the controller to a memory store with the job record the
// queue would have created.
func newController(t *testing.T, reg *fakeRegistry, cl *fakeClair) (Controller, persistence.Store) {
	t.Helper()
	store := memory.NewStore()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{ID: testJobID, Status: job.Queued}))
	return NewController(store, cl, reg, harbor.ClairScanner()), store
}

func TestController_Scan(t *testing.T) {
	reg := &fakeRegistry{manifest: testManifest()}
	cl := &fakeClair{
		indexReport: finishedIndexReport(),
		report: &clair.VulnerabilityReport{
			ManifestHash:           artifactDigest,
			Packages:               map[string]*clair.Package{"1": {ID: "1", Name: "musl", Version: "1.1.22-r3"}},
			Vulnerabilities:        map[string]*clair.Vulnerability{"9": {ID: "9", Name: "CVE-2019-14697", NormalizedSeverity: "High", FixedInVersion: "1.1.22-r4"}},
			PackageVulnerabilities: map[string][]string{"1": {"9"}},
		},
	}
	controller, store := newController(t, reg, cl)

	require.NoError(t, controller.Scan(context.Background(), testJobID, testScanRequest()))

	// The Clair manifest is built from the fetched manifest, in layer order,
	// with the scan authorization forwarded verbatim.
	assert.Equal(t, clair.Manifest{
		Hash: artifactDigest,
		Layers: []clair.Layer{
			{
				Hash:    layerDigestA,
				URI:     "https://harbor.example.com/v2/library/alpine/blobs/" + layerDigestA,
				Headers: map[string][]string{"Authorization": {testAuthValue}},
			},
			{
				Hash:    layerDigestB,
				URI:     "https://harbor.example.com/v2/library/alpine/blobs/" + layerDigestB,
				Headers: map[string][]string{"Authorization": {testAuthValue}},
			},
		},
	}, cl.indexed)
	// The request's digest, not whatever Clair echoed back on the index report.
	assert.Equal(t, artifactDigest, cl.reportedHash)

	scanJob, err := store.Get(context.Background(), testJobID)
	require.NoError(t, err)
	require.NotNil(t, scanJob)
	assert.Equal(t, job.Finished, scanJob.Status)

	var report harbor.ScanReport
	require.NoError(t, json.Unmarshal(scanJob.Report, &report))
	assert.Equal(t, harbor.ClairScanner(), report.Scanner)
	assert.Equal(t, artifactDigest, report.Artifact.Digest)
	require.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2019-14697", report.Vulnerabilities[0].ID)
}

// The stored error string is what Harbor renders as the scan job's failure
// detail, so every failure mode has to arrive with the category prefix an
// operator acts on.
func TestController_ScanFailureCategories(t *testing.T) {
	transportError := &net.OpError{Op: "dial", Err: errors.New("connection refused")}

	testCases := []struct {
		name           string
		registry       *fakeRegistry
		clair          *fakeClair
		expectedPrefix string
	}{
		{
			name:           "registry auth",
			registry:       &fakeRegistry{err: fmt.Errorf("getting manifest: %w", registry.ErrRegistryAuth)},
			clair:          &fakeClair{},
			expectedPrefix: "[auth] fetching the artifact manifest",
		},
		{
			name:           "missing manifest",
			registry:       &fakeRegistry{err: fmt.Errorf("%w: 404", registry.ErrManifestNotFound)},
			clair:          &fakeClair{},
			expectedPrefix: "[manifest] fetching the artifact manifest",
		},
		{
			name:           "unscannable layer",
			registry:       &fakeRegistry{err: fmt.Errorf("%w: cosign", registry.ErrUnscannableLayer)},
			clair:          &fakeClair{},
			expectedPrefix: "[unscannable_layer] fetching the artifact manifest",
		},
		{
			name:           "unsupported artifact",
			registry:       &fakeRegistry{err: fmt.Errorf("%w: an image index", registry.ErrUnsupportedArtifact)},
			clair:          &fakeClair{},
			expectedPrefix: "[unscannable_layer] fetching the artifact manifest",
		},
		{
			name:           "registry transport failure",
			registry:       &fakeRegistry{err: fmt.Errorf("getting manifest: %w", transportError)},
			clair:          &fakeClair{},
			expectedPrefix: "[network] fetching the artifact manifest",
		},
		{
			name:           "clair rejects the credentials",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexErr: fmt.Errorf("%w: 401", clair.ErrUnauthorized)},
			expectedPrefix: "[auth] indexing the artifact",
		},
		{
			name:           "clair fails the index",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexErr: fmt.Errorf("%w: tarfs", clair.ErrIndexFailed)},
			expectedPrefix: "[clair_index] indexing the artifact",
		},
		{
			name:     "clair reports an unfinished index",
			registry: &fakeRegistry{manifest: testManifest()},
			clair: &fakeClair{
				indexReport: &clair.IndexReport{State: clair.StateIndexError, Err: "fetching layer failed"},
			},
			expectedPrefix: "[clair_index] indexing the artifact",
		},
		{
			name:           "clair is unavailable",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexReport: finishedIndexReport(), reportErr: fmt.Errorf("%w: 503", clair.ErrServerError)},
			expectedPrefix: "[clair_unavailable] getting the vulnerability report",
		},
		{
			name:           "the matcher never initialized",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexReport: finishedIndexReport(), reportErr: fmt.Errorf("%w", clair.ErrMatcherNotReady)},
			expectedPrefix: "[clair_unavailable] getting the vulnerability report",
		},
		{
			name:           "the report was truncated",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexReport: finishedIndexReport(), reportErr: fmt.Errorf("%w", clair.ErrReportTruncated)},
			expectedPrefix: "[report_parse] getting the vulnerability report",
		},
		{
			name:           "the job ran out of time",
			registry:       &fakeRegistry{manifest: testManifest()},
			clair:          &fakeClair{indexErr: fmt.Errorf("indexing: %w", context.DeadlineExceeded)},
			expectedPrefix: "[timeout] indexing the artifact",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			controller, store := newController(t, tc.registry, tc.clair)

			// A failed scan is a recorded outcome, not an error the worker
			// retries, so Scan itself returns nil.
			require.NoError(t, controller.Scan(context.Background(), testJobID, testScanRequest()))

			scanJob, err := store.Get(context.Background(), testJobID)
			require.NoError(t, err)
			require.NotNil(t, scanJob)
			assert.Equal(t, job.Failed, scanJob.Status)
			assert.Truef(t, len(scanJob.Error) > 0 && scanJob.Error[0] == '[',
				"the stored error must carry a category prefix, got %q", scanJob.Error)
			assert.Contains(t, scanJob.Error, tc.expectedPrefix)
		})
	}
}

// An artifact digest Clair's schema cannot accept never reaches the registry.
func TestController_ScanRejectsAnUnusableDigest(t *testing.T) {
	for _, tc := range []struct{ name, digest string }{
		{"not a digest", "latest"},
		{"not sha256", "sha512:0f5f1b1d2b8ae4d4b1ee1ee62a52ffb3f7f5a0d5a5a2e5f7bcbb0a0dd3f6d4b10f5f1b1d2b8ae4d4b1ee1ee62a52ffb3f7f5a0d5a5a2e5f7bcbb0a0dd3f6d4b1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistry{manifest: testManifest()}
			controller, store := newController(t, reg, &fakeClair{})

			req := testScanRequest()
			req.Artifact.Digest = tc.digest
			require.NoError(t, controller.Scan(context.Background(), testJobID, req))

			assert.Zero(t, reg.calls)
			scanJob, err := store.Get(context.Background(), testJobID)
			require.NoError(t, err)
			require.NotNil(t, scanJob)
			assert.Equal(t, job.Failed, scanJob.Status)
			assert.Contains(t, scanJob.Error, "[manifest] validating the artifact digest")
		})
	}
}

// A record that expired while the job was queued is a capacity symptom. There is
// nothing left to write a Failed status to, and Harbor learns the scan is gone
// from the 404 it is already polling.
func TestController_ScanWritesNothingWhenTheRecordIsGone(t *testing.T) {
	store := memory.NewStore()
	controller := NewController(store, &fakeClair{}, &fakeRegistry{manifest: testManifest()}, harbor.ClairScanner())

	require.NoError(t, controller.Scan(context.Background(), testJobID, testScanRequest()))

	scanJob, err := store.Get(context.Background(), testJobID)
	require.NoError(t, err)
	assert.Nil(t, scanJob)
}

// ctxStore rejects writes on an expired context, the way pgx does. The memory
// store ignores ctx, so it cannot exercise the detached terminal write on its
// own.
type ctxStore struct {
	persistence.Store
}

func (s ctxStore) Finish(ctx context.Context, scanJobID string, report json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.Finish(ctx, scanJobID, report)
}

func (s ctxStore) UpdateStatus(ctx context.Context, scanJobID string, status job.ScanJobStatus, msg ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.UpdateStatus(ctx, scanJobID, status, msg...)
}

func queuedCtxStore(t *testing.T) (ctxStore, persistence.Store) {
	t.Helper()
	base := memory.NewStore()
	require.NoError(t, base.Create(context.Background(), job.ScanJob{ID: testJobID, Status: job.Queued}))
	return ctxStore{Store: base}, base
}

// The per-job deadline firing is how most failures arrive, and the terminal
// write must still land: pgx fails every query on an expired context, so a job
// written on the job context would stay Pending until its TTL.
func TestController_ScanTerminalWriteSurvivesACanceledContext(t *testing.T) {
	t.Run("finished", func(t *testing.T) {
		store, base := queuedCtxStore(t)
		reg := &fakeRegistry{manifest: testManifest()}
		cl := &fakeClair{indexReport: finishedIndexReport(), report: &clair.VulnerabilityReport{ManifestHash: artifactDigest}}
		controller := NewController(store, cl, reg, harbor.ClairScanner())

		// The job context dies mid-scan, after the Pending write and before the
		// Finish write, so only the detached write can land the result.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cl.onReport = cancel
		require.NoError(t, controller.Scan(ctx, testJobID, testScanRequest()))

		scanJob, err := base.Get(context.Background(), testJobID)
		require.NoError(t, err)
		require.NotNil(t, scanJob)
		assert.Equal(t, job.Finished, scanJob.Status, "the terminal write must not inherit the dead job context")
	})

	t.Run("failed", func(t *testing.T) {
		store, base := queuedCtxStore(t)
		reg := &fakeRegistry{manifest: testManifest()}
		controller := NewController(store, &fakeClair{}, reg, harbor.ClairScanner())

		// Already canceled on entry: the Pending write fails with
		// context.Canceled and the Failed write must still land.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		require.NoError(t, controller.Scan(ctx, testJobID, testScanRequest()))

		scanJob, err := base.Get(context.Background(), testJobID)
		require.NoError(t, err)
		require.NotNil(t, scanJob)
		assert.Equal(t, job.Failed, scanJob.Status, "the terminal write must not inherit the dead job context")
		assert.Contains(t, scanJob.Error, "[timeout]")
	})
}

// A panic in the scan path is the adapter's own bug and must be recorded as
// such, not left to take the worker goroutine down with it.
func TestController_ScanRecoversFromAPanic(t *testing.T) {
	reg := &fakeRegistry{manifest: nil} // ClairManifest on a nil manifest panics.
	controller, store := newController(t, reg, &fakeClair{})

	require.NoError(t, controller.Scan(context.Background(), testJobID, testScanRequest()))

	scanJob, err := store.Get(context.Background(), testJobID)
	require.NoError(t, err)
	require.NotNil(t, scanJob)
	assert.Equal(t, job.Failed, scanJob.Status)
	assert.Contains(t, scanJob.Error, "[adapter] scanning the artifact: panic")
}

func TestErrorCategory(t *testing.T) {
	assert.Equal(t, "none", errorCategory(nil))
	assert.Equal(t, "Expired", errorCategory(fmt.Errorf("wrapped: %w", persistence.ErrJobNotFound)))
	assert.Equal(t, "auth", errorCategory(&Error{Category: CategoryAuth, Detail: "d", Cause: errors.New("c")}))
	assert.Equal(t, "adapter", errorCategory(errors.New("something unexpected")))
}
