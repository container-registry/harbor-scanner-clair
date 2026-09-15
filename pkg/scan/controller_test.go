package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence/memory"
)

const (
	testJobID     = "job-1"
	configDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	layerDigestA  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	layerDigestB  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	testAuthValue = "Bearer harbor-minted-token"
)

// fakeManifest is the smallest thing that satisfies distribution.Manifest; the
// controller only ever calls References().
type fakeManifest struct {
	refs []distribution.Descriptor
}

func (m fakeManifest) References() []distribution.Descriptor { return m.refs }
func (m fakeManifest) Payload() (string, []byte, error)      { return "", nil, nil }

type fakeRegistry struct {
	manifest distribution.Manifest
	err      error
	panics   bool
}

func (r *fakeRegistry) GetManifest(harbor.ScanRequest) (distribution.Manifest, error) {
	if r.panics {
		panic("registry client exploded")
	}
	return r.manifest, r.err
}

type fakeClair struct {
	scanned  []clair.Layer
	envelope *clair.LayerEnvelope
	scanErr  error
	getErr   error
}

func (c *fakeClair) ScanLayer(layer clair.Layer) error {
	c.scanned = append(c.scanned, layer)
	return c.scanErr
}

func (c *fakeClair) GetLayer(string) (*clair.LayerEnvelope, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	return c.envelope, nil
}

func manifestWithTwoLayers() distribution.Manifest {
	return fakeManifest{refs: []distribution.Descriptor{
		{MediaType: "application/vnd.docker.container.image.v1+json", Digest: digest.Digest(configDigest)},
		{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: digest.Digest(layerDigestA)},
		{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: digest.Digest(layerDigestB)},
	}}
}

func scanRequest() harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://core.harbor.domain", Authorization: testAuthValue},
		Artifact: harbor.Artifact{Repository: "library/alpine", Digest: layerDigestB},
	}
}

func testScanner() harbor.Scanner {
	return harbor.Scanner{Name: "Clair", Vendor: "CoreOS", Version: "2.x"}
}

func queuedStore(t *testing.T) persistence.Store {
	t.Helper()
	store := memory.NewStore()
	require.NoError(t, store.Create(context.Background(), job.ScanJob{ID: testJobID, Status: job.Queued}))
	return store
}

func TestControllerScanHappyPath(t *testing.T) {
	store := queuedStore(t)
	clairClient := &fakeClair{envelope: &clair.LayerEnvelope{Layer: &clair.Layer{
		Features: []clair.Feature{{
			Name:    "openssl",
			Version: "1.1.1",
			Vulnerabilities: []clair.Vulnerability{{
				Name:        "CVE-2019-1111",
				Severity:    "High",
				Description: "an example",
				FixedBy:     "1.1.2",
				Link:        "https://example.test/CVE-2019-1111",
			}},
		}},
	}}}
	registryClient := &fakeRegistry{manifest: manifestWithTwoLayers()}

	c := NewController(store, clairClient, registryClient, testScanner())
	require.NoError(t, c.Scan(context.Background(), testJobID, scanRequest()))

	got, err := store.Get(context.Background(), testJobID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)
	assert.Empty(t, got.Error)

	var report harbor.ScanReport
	require.NoError(t, json.Unmarshal(got.Report, &report))
	assert.Equal(t, testScanner(), report.Scanner)
	assert.Equal(t, harbor.SevHigh, report.Severity)
	require.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2019-1111", report.Vulnerabilities[0].ID)

	// The image config is not a layer, so only the two rootfs layers are sent,
	// each with the authorization Harbor minted for this scan.
	require.Len(t, clairClient.scanned, 2)
	assert.Equal(t, "https://core.harbor.domain/v2/library/alpine/blobs/"+layerDigestA, clairClient.scanned[0].Path)
	assert.Equal(t, "https://core.harbor.domain/v2/library/alpine/blobs/"+layerDigestB, clairClient.scanned[1].Path)
	assert.Equal(t, testAuthValue, clairClient.scanned[1].Headers["Authorization"])
	assert.Equal(t, clairClient.scanned[0].Name, clairClient.scanned[1].ParentName,
		"layers must be chained so Clair can reuse a shared base")
}

// TestControllerScanRecordsFailures pins that every failure reaches the store as
// a Failed record with the cause. Harbor surfaces that text, so a scan that
// fails silently is a scan an operator cannot debug.
func TestControllerScanRecordsFailures(t *testing.T) {
	testCases := []struct {
		name           string
		registry       *fakeRegistry
		clair          *fakeClair
		expectedErrMsg string
	}{
		{
			name:           "manifest fetch fails",
			registry:       &fakeRegistry{err: errors.New("registry is down")},
			clair:          &fakeClair{},
			expectedErrMsg: "getting manifest: registry is down",
		},
		{
			name:           "manifest references no layer",
			registry:       &fakeRegistry{manifest: fakeManifest{}},
			clair:          &fakeClair{},
			expectedErrMsg: "no scannable layers",
		},
		{
			name:           "clair rejects a layer",
			registry:       &fakeRegistry{manifest: manifestWithTwoLayers()},
			clair:          &fakeClair{scanErr: errors.New("unexpected status code: 500")},
			expectedErrMsg: "unexpected status code: 500",
		},
		{
			name:           "clair cannot return the report",
			registry:       &fakeRegistry{manifest: manifestWithTwoLayers()},
			clair:          &fakeClair{getErr: errors.New("unexpected status code: 404")},
			expectedErrMsg: "unexpected status code: 404",
		},
		{
			// The recover() keeps one malformed artifact from taking the whole
			// worker goroutine, and therefore all scanning, down with it.
			name:           "a panic is recorded, not propagated",
			registry:       &fakeRegistry{panics: true},
			clair:          &fakeClair{},
			expectedErrMsg: "panic during scan",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := queuedStore(t)
			c := NewController(store, tc.clair, tc.registry, testScanner())

			require.NoError(t, c.Scan(context.Background(), testJobID, scanRequest()),
				"a failed scan is a recorded outcome, not an error returned to the worker")

			got, err := store.Get(context.Background(), testJobID)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, job.Failed, got.Status)
			assert.Contains(t, got.Error, tc.expectedErrMsg)
		})
	}
}

// TestControllerScanIgnoresAVanishedRecord pins that a job whose store record
// expired while it was queued is not reported as a scan failure: there is
// nothing left to write a status to, and Harbor already learns it is gone from
// the 404 on its next poll.
func TestControllerScanIgnoresAVanishedRecord(t *testing.T) {
	store := memory.NewStore() // no record created
	c := NewController(store, &fakeClair{}, &fakeRegistry{manifest: manifestWithTwoLayers()}, testScanner())

	require.NoError(t, c.Scan(context.Background(), testJobID, scanRequest()))

	got, err := store.Get(context.Background(), testJobID)
	require.NoError(t, err)
	assert.Nil(t, got, "nothing must be resurrected for a job whose record is gone")
}

// ctxStore rejects writes on an expired context, the way the database driver
// does. The
// memory store ignores ctx, so it cannot exercise the detached terminal write
// on its own.
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

// TestTerminalWriteSurvivesAnExpiredJobContext pins the detached write. The job
// context carries the per-job deadline, and the database driver fails every
// query on an expired context: reusing it would leave a finished job stuck
// Pending until its TTL while Harbor polled it.
func TestTerminalWriteSurvivesAnExpiredJobContext(t *testing.T) {
	base := queuedStore(t)
	store := ctxStore{Store: base}

	// A clock that cancels the job context the moment the report is built, so
	// the only write left to make is the terminal one.
	ctx, cancel := context.WithCancel(context.Background())
	clairClient := &cancellingClair{cancel: cancel, envelope: &clair.LayerEnvelope{Layer: &clair.Layer{}}}

	c := NewController(store, clairClient, &fakeRegistry{manifest: manifestWithTwoLayers()}, testScanner())
	require.NoError(t, c.Scan(ctx, testJobID, scanRequest()))

	got, err := base.Get(context.Background(), testJobID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status, "the terminal write must not inherit the dead job context")
}

// cancellingClair cancels the job context after the last Clair call, which is
// where a per-job deadline realistically fires.
type cancellingClair struct {
	cancel   context.CancelFunc
	envelope *clair.LayerEnvelope
}

func (c *cancellingClair) ScanLayer(clair.Layer) error { return nil }

func (c *cancellingClair) GetLayer(string) (*clair.LayerEnvelope, error) {
	c.cancel()
	return c.envelope, nil
}
