// Package scan orchestrates one scan job: fetch the artifact manifest from the
// registry, hand the layers to Clair, and turn Clair's answer into the report
// Harbor polls for.
//
// This controller is a transitional shape: it drives the Clair v4 client
// through a local interface, and the registry client and error categories it
// deserves arrive with the rest of the scan-path rewrite.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/docker/distribution"
)

// statusWriteTimeout bounds the terminal status/report writes. Those writes run
// on a context detached from the per-job deadline (queue.runJob) so a job that
// hit the deadline is still recorded as Failed, and a job that finished just
// under the deadline is still recorded as Finished. The database driver fails
// any query on an expired context, so reusing the job context here would leave
// the job stuck Pending until its TTL, and Harbor would 302-poll it for up to
// ScanJobTTL before 404ing.
const statusWriteTimeout = 10 * time.Second

// clairClient is the subset of the Clair API one scan needs. It is a local
// interface so the client behind it can be replaced without touching the
// orchestration.
type clairClient interface {
	Index(ctx context.Context, m clair.Manifest) (*clair.IndexReport, error)
	VulnerabilityReport(ctx context.Context, manifestHash string) (*clair.VulnerabilityReport, error)
}

// Image config media types. Clair indexes filesystem layers, and the config
// blob is neither a layer nor a tar, so it is skipped for both the Docker and
// the OCI spelling.
const (
	mediaTypeDockerImageConfig = "application/vnd.docker.container.image.v1+json"
	mediaTypeOCIImageConfig    = "application/vnd.oci.image.config.v1+json"
)

// registryClient fetches the artifact manifest with the authorization Harbor
// minted for this scan.
type registryClient interface {
	GetManifest(req harbor.ScanRequest) (distribution.Manifest, error)
}

type Controller interface {
	Scan(ctx context.Context, jobID string, req harbor.ScanRequest) error
}

type controller struct {
	store       persistence.Store
	clair       clairClient
	registry    registryClient
	transformer *Transformer
	scanner     harbor.Scanner
}

func NewController(store persistence.Store, clairClient clairClient, registryClient registryClient, scanner harbor.Scanner) Controller {
	return &controller{
		store:       store,
		clair:       clairClient,
		registry:    registryClient,
		transformer: NewTransformer(),
		scanner:     scanner,
	}
}

func (c *controller) Scan(ctx context.Context, jobID string, req harbor.ScanRequest) error {
	metrics.ScansInFlight.Inc()
	started := time.Now()

	err := c.scan(ctx, jobID, req)

	metrics.ScansInFlight.Dec()
	metrics.ObserveScan(err == nil, errorCategory(err), time.Since(started).Seconds())

	if err != nil {
		errMsg := err.Error()
		// A vanished record is a capacity symptom, not a scan failure, and there
		// is nothing left to write the Failed status to. Harbor is already
		// polling a key that 404s, which is how it learns the scan is gone.
		if errors.Is(err, persistence.ErrJobNotFound) {
			slog.Warn("Scan job record is gone; it outlived the scan job TTL while queued",
				slog.String("scan_job_id", jobID), slog.String("err", errMsg))
			return nil
		}
		slog.Error("Scan failed", slog.String("scan_job_id", jobID), slog.String("err", errMsg))
		// Detach from ctx: the per-job deadline may already have fired (that is
		// precisely how most failures arrive), and the Failed write must land.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
		defer cancel()
		if uErr := c.store.UpdateStatus(writeCtx, jobID, job.Failed, errMsg); uErr != nil {
			return fmt.Errorf("updating scan job as failed: %w", uErr)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, jobID string, req harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during scan: %v", r)
		}
	}()

	if err = c.store.UpdateStatus(ctx, jobID, job.Pending); err != nil {
		return fmt.Errorf("updating scan job status: %w", err)
	}

	manifest, err := c.registry.GetManifest(req)
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	clairManifest, err := toClairManifest(req, manifest)
	if err != nil {
		return err
	}

	// Clair fetches every layer itself over the URIs and headers in the
	// manifest, so this one call covers the whole artifact and blocks until the
	// index is finished.
	indexReport, err := c.clair.Index(ctx, clairManifest)
	if err != nil {
		return fmt.Errorf("indexing artifact: %w", err)
	}
	slog.Debug("Artifact indexed",
		slog.String("scan_job_id", jobID),
		slog.String("state", indexReport.State),
		slog.Int("layers", len(clairManifest.Layers)))

	vulnerabilityReport, err := c.clair.VulnerabilityReport(ctx, clairManifest.Hash)
	if err != nil {
		return fmt.Errorf("getting vulnerability report: %w", err)
	}

	report := c.transformer.Transform(req.Artifact, c.scanner, vulnerabilityReport)
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshaling report envelope: %w", err)
	}

	slog.Info("Scan finished",
		slog.String("scan_job_id", jobID),
		slog.String("repository", req.Artifact.Repository),
		slog.String("digest", req.Artifact.Digest))

	// The terminal write runs detached from the job deadline: a scan that
	// completed just under the deadline must still be recorded as Finished, not
	// lost to an expired context.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()
	if err = c.store.Finish(writeCtx, jobID, raw); err != nil {
		return fmt.Errorf("saving scan report: %w", err)
	}
	return nil
}

// toClairManifest describes the artifact the way Clair's indexer wants it: the
// artifact digest as the manifest hash, one entry per layer in manifest order,
// and the pull token Harbor minted for this scan forwarded verbatim as the
// header Clair fetches each blob with.
func toClairManifest(req harbor.ScanRequest, manifest distribution.Manifest) (clair.Manifest, error) {
	clairManifest := clair.Manifest{Hash: req.Artifact.Digest}
	registryURL := strings.TrimRight(req.Registry.URL, "/")

	for _, descriptor := range manifest.References() {
		if descriptor.MediaType == mediaTypeDockerImageConfig || descriptor.MediaType == mediaTypeOCIImageConfig {
			continue
		}
		clairManifest.Layers = append(clairManifest.Layers, clair.Layer{
			Hash: descriptor.Digest.String(),
			URI:  fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, req.Artifact.Repository, descriptor.Digest),
			// Headers are map[string][]string on the wire. Only Authorization
			// is sent: Clair follows the registry's redirect to storage itself,
			// and Go drops the header on a cross-host hop, which is what makes
			// a presigned URL work.
			Headers: map[string][]string{"Authorization": {req.Registry.Authorization}},
		})
	}

	if len(clairManifest.Layers) == 0 {
		return clair.Manifest{}, fmt.Errorf("no scannable layers in artifact %s", req.Artifact.Digest)
	}
	return clairManifest, nil
}

// errorCategory maps a scan failure onto the metrics category label. A record
// that expired while queued is a capacity signal and gets its own label rather
// than being counted as an adapter fault.
func errorCategory(err error) string {
	switch {
	case err == nil:
		return metrics.CategoryNone
	case errors.Is(err, persistence.ErrJobNotFound):
		return metrics.CategoryExpired
	default:
		return metrics.CategoryAdapter
	}
}
