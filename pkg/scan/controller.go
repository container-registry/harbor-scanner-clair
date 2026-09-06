// Package scan orchestrates one scan job: fetch the artifact manifest from the
// registry, hand the layers to Clair, and turn Clair's answer into the report
// Harbor polls for.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/registry"
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

// registryClient fetches the artifact manifest with the authorization Harbor
// minted for this scan.
type registryClient interface {
	GetManifest(ctx context.Context, req harbor.ScanRequest) (*registry.Manifest, error)
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
			err = &Error{Category: CategoryAdapter, Detail: "scanning the artifact", Cause: fmt.Errorf("panic: %v", r)}
		}
	}()

	if err = c.store.UpdateStatus(ctx, jobID, job.Pending); err != nil {
		return fail("updating scan job status", err)
	}

	if err = validateDigest(req.Artifact.Digest); err != nil {
		return err
	}

	manifest, err := c.registry.GetManifest(ctx, req)
	if err != nil {
		return fail("fetching the artifact manifest", err)
	}
	clairManifest := manifest.ClairManifest(req)

	// Clair fetches every layer itself over the URIs and headers in the
	// manifest, so this one call covers the whole artifact and blocks until the
	// index is finished.
	indexReport, err := c.clair.Index(ctx, clairManifest)
	if err != nil {
		return fail("indexing the artifact", err)
	}
	// The client already rejects an unsuccessful 201. This second check covers
	// every other status that yields a report body, so an unfinished index can
	// never be read as a clean one and reported to Harbor as zero findings.
	if indexReport.State != clair.StateIndexFinished || !indexReport.Success {
		return &Error{
			Category: CategoryClairIndex,
			Detail:   "indexing the artifact",
			Cause: fmt.Errorf("%w: state %q: %s",
				clair.ErrIndexFailed, indexReport.State, indexReport.Err),
		}
	}
	slog.Debug("Artifact indexed",
		slog.String("scan_job_id", jobID),
		slog.String("state", indexReport.State),
		slog.Int("layers", len(clairManifest.Layers)))

	// The request's digest, not the one Clair echoed back: they are the same
	// value, and using this one keeps the two calls independent.
	vulnerabilityReport, err := c.clair.VulnerabilityReport(ctx, req.Artifact.Digest)
	if err != nil {
		return fail("getting the vulnerability report", err)
	}

	report := c.transformer.Transform(req.Artifact, c.scanner, vulnerabilityReport)
	raw, err := json.Marshal(report)
	if err != nil {
		return fail("marshaling the report envelope", err)
	}

	slog.Info("Scan finished",
		slog.String("scan_job_id", jobID),
		slog.String("repository", req.Artifact.Repository),
		slog.String("digest", req.Artifact.Digest),
		slog.Int("vulnerabilities", len(report.Vulnerabilities)))

	// The terminal write runs detached from the job deadline: a scan that
	// completed just under the deadline must still be recorded as Finished, not
	// lost to an expired context.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()
	if err = c.store.Finish(writeCtx, jobID, raw); err != nil {
		return fail("saving the scan report", err)
	}
	return nil
}

// validateDigest rejects an artifact digest Clair's schema would not accept.
// The API handler validates the same thing on the way in; repeating it here
// keeps the worker safe for any other producer, and the failure is categorized
// as a manifest problem because the digest is how the manifest is addressed.
func validateDigest(value string) error {
	parsed, err := digest.Parse(value)
	if err != nil {
		return &Error{Category: CategoryManifest, Detail: "validating the artifact digest", Cause: err}
	}
	if parsed.Algorithm() != digest.SHA256 {
		return &Error{
			Category: CategoryManifest,
			Detail:   "validating the artifact digest",
			Cause: fmt.Errorf("digest %q is not sha256, which is the only algorithm clair accepts",
				value),
		}
	}
	return nil
}

// fail attaches the category Harbor will render to a step failure. The stored
// job error string is exactly what Harbor shows as the scan job's failure
// detail, so the [category] prefix is what turns it into an actionable message.
func fail(detail string, err error) error {
	return &Error{Category: Categorize(err), Detail: detail, Cause: err}
}

// errorCategory maps a scan failure onto the metrics category label, which uses
// the same vocabulary as the error prefix. A record that expired while queued is
// a capacity signal and gets its own label rather than being counted as an
// adapter fault.
func errorCategory(err error) string {
	switch {
	case err == nil:
		return metrics.CategoryNone
	case errors.Is(err, persistence.ErrJobNotFound):
		return metrics.CategoryExpired
	default:
		return string(Categorize(err))
	}
}
