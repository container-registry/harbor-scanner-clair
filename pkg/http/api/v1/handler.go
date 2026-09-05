// Package v1 implements the Harbor Scanner Adapter API v1: /metadata, /scan,
// /scan/{id}/report, the probes and the metrics endpoint.
package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/http/api"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/queue"
)

const (
	pathVarScanRequestID = "scan_request_id"

	// headerAPIKey guards /api/v1 when SCANNER_API_AUTH_API_KEY is set.
	headerAPIKey = "X-ScannerAdapter-API-Key"

	// refreshAfter is the report poll hint. Harbor parses Refresh-After with
	// ParseInt(v, 10, 8), so it MUST be <= 127. 5 seconds.
	refreshAfter = "5"

	// registryAuthorizationType is advertised so Harbor mints a pull-scoped
	// registry token and the adapter can forward it to Clair verbatim.
	registryAuthorizationType = "Bearer"

	propertyScannerType   = "harbor.scanner-adapter/scanner-type"
	propertyRegistryAuth  = "harbor.scanner-adapter/registry-authorization-type"
	propertyVulnDBUpdated = "harbor.scanner-adapter/vulnerability-database-updated-at"

	vcsURL = "https://github.com/container-registry/harbor-scanner-clair"
)

// ReadyFunc reports whether the adapter can serve scans. A non-nil error
// answers /probe/ready with 503.
type ReadyFunc func(ctx context.Context) error

// VulnDBUpdatedAtFunc reports when Clair last finished a vulnerability update.
// The second result is false when the answer is not available, in which case the
// metadata property is omitted rather than reported as a zero time.
type VulnDBUpdatedAtFunc func(ctx context.Context) (time.Time, bool)

type requestHandler struct {
	info            etc.BuildInfo
	config          etc.Config
	scanner         harbor.Scanner
	enqueuer        queue.Enqueuer
	store           persistence.Store
	ready           ReadyFunc
	vulnDBUpdatedAt VulnDBUpdatedAtFunc
	api.BaseHandler
}

func NewAPIHandler(
	info etc.BuildInfo,
	config etc.Config,
	scanner harbor.Scanner,
	enqueuer queue.Enqueuer,
	store persistence.Store,
	ready ReadyFunc,
	vulnDBUpdatedAt VulnDBUpdatedAtFunc,
) http.Handler {
	handler := &requestHandler{
		info:            info,
		config:          config,
		scanner:         scanner,
		enqueuer:        enqueuer,
		store:           store,
		ready:           ready,
		vulnDBUpdatedAt: vulnDBUpdatedAt,
	}

	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	if config.API.APIKey != "" {
		apiV1Router.Use(handler.requireAPIKey)
	}
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.GetMetadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.AcceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.GetScanReport)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.GetHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.GetReady)

	if config.API.MetricsEnabled {
		router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())
	}
	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request",
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("uri", r.URL.RequestURI()))
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerAPIKey) != h.config.API.APIKey {
			h.WriteJSONError(w, api.Error{HTTPCode: http.StatusUnauthorized, Message: "invalid api key"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	if err := json.NewDecoder(req.Body).Decode(&scanRequest); err != nil {
		slog.Error("Error while unmarshalling scan request", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.validate(scanRequest); validationError != nil {
		slog.Error("Error while validating scan request", slog.String("err", validationError.Message))
		h.WriteJSONError(res, *validationError)
		return
	}

	jobID, err := h.enqueuer.Enqueue(req.Context(), scanRequest)
	if err != nil {
		slog.Error("Error while enqueuing scan job", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, harbor.ScanResponse{ID: jobID}, api.MimeTypeScanResponse, http.StatusAccepted)
}

// validate answers every contract violation synchronously as a 422. Everything
// checked here used to be 202-accepted and then failed inside a worker, where
// Harbor sees it as a scan failure rather than as the bad request it is.
func (h *requestHandler) validate(req harbor.ScanRequest) *api.Error {
	if err := validateCapabilities(req.Capabilities); err != nil {
		return err
	}

	if req.Registry.URL == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing registry.url"}
	}
	// Scheme and host are required, not just parseability: the blob URLs handed
	// to Clair are built from them, so "core.harbor.domain" (no scheme) or
	// "ftp://..." produces a URL Clair cannot fetch.
	registryURL, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil || registryURL.Host == "" || (registryURL.Scheme != "http" && registryURL.Scheme != "https") {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "invalid registry.url: expected an absolute http(s) URL"}
	}

	if req.Artifact.Repository == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing artifact.repository"}
	}
	if req.Artifact.Digest == "" {
		return &api.Error{HTTPCode: http.StatusUnprocessableEntity, Message: "missing artifact.digest"}
	}
	// Clair keys an index report by the manifest digest and rejects anything but
	// sha256, so a malformed digest is a request the adapter can never satisfy.
	parsed, err := digest.Parse(req.Artifact.Digest)
	if err != nil {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  fmt.Sprintf("invalid artifact.digest: %s", err),
		}
	}
	if parsed.Algorithm() != digest.SHA256 {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  fmt.Sprintf("unsupported artifact.digest algorithm %q: only sha256 is supported", parsed.Algorithm()),
		}
	}

	// registry.authorization is opaque and forwarded to Clair verbatim as each
	// layer's Authorization header, so it is not decoded here. An empty value is
	// an anonymous pull from a public project and is allowed; any other scheme
	// means the scanner registration disagrees with the advertised
	// registry-authorization-type and every layer fetch would 401.
	if authorization := strings.TrimSpace(req.Registry.Authorization); authorization != "" {
		scheme, credentials, ok := strings.Cut(authorization, " ")
		// RFC 9110 makes the scheme case-insensitive.
		if !ok || !strings.EqualFold(scheme, registryAuthorizationType) || credentials == "" {
			return &api.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message: fmt.Sprintf("invalid registry.authorization; this adapter advertises %s registry authorization -- "+
					"a non-%s authorization indicates a misconfigured scanner registration", registryAuthorizationType, registryAuthorizationType),
			}
		}
	}

	return nil
}

func validateCapabilities(capabilities []harbor.Capability) *api.Error {
	for _, c := range capabilities {
		// Harbor's hasCapability is MIME-based, so an SBOM trigger against this
		// registration should never reach here. A direct client still can.
		if c.Type == harbor.CapabilityTypeSBOM {
			return &api.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message: "this adapter only produces vulnerability reports; " +
					"register an SBOM-capable adapter (trivy, dependency-track) for sbom generation",
			}
		}
		if c.Type != "" && c.Type != harbor.CapabilityTypeVulnerability {
			return &api.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  fmt.Sprintf("unsupported scan type: %q", c.Type),
			}
		}
		// Every requested produces MIME must be one this adapter can serve.
		// Without this check a request asking only for report types the adapter
		// does not produce was acknowledged and then answered with a 415 on
		// every poll until the job TTL expired.
		for _, produces := range c.ProducesMIMETypes {
			var m api.MIMEType
			if err := m.Parse(produces); err != nil {
				return &api.Error{
					HTTPCode: http.StatusUnprocessableEntity,
					Message:  fmt.Sprintf("unsupported produces mime type: %q", produces),
				}
			}
		}
	}
	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	jobID, ok := mux.Vars(req)[pathVarScanRequestID]
	if !ok {
		slog.Error("Error while parsing `scan_request_id` path variable")
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusBadRequest, Message: "missing scan_request_id"})
		return
	}
	reqLog := slog.With(slog.String("scan_job_id", jobID))

	var reportMIMEType api.MIMEType
	if err := reportMIMEType.Parse(req.Header.Get(api.HeaderAccept)); err != nil {
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusUnsupportedMediaType,
			Message:  fmt.Sprintf("unsupported media type: %q", req.Header.Get(api.HeaderAccept)),
		})
		return
	}

	scanJob, err := h.store.Get(req.Context(), jobID)
	if err != nil {
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}
	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", jobID),
		})
		return
	}

	switch scanJob.Status {
	case job.Queued, job.Pending:
		reqLog.Debug("Scan job has not finished yet", slog.String("scan_job_status", scanJob.Status.String()))
		res.Header().Set("Location", req.URL.String())
		res.Header().Set(api.HeaderRefreshAfter, refreshAfter)
		res.WriteHeader(http.StatusFound)
	case job.Failed:
		reqLog.Error("Scan job failed", slog.String("err", scanJob.Error))
		h.WriteJSONError(res, api.Error{HTTPCode: http.StatusInternalServerError, Message: scanJob.Error})
	case job.Finished:
		// Stream the stored bytes. Re-marshaling the report on every poll costs
		// Harbor's 5s per-request budget for nothing.
		h.WriteRawJSON(res, req, scanJob.Report, reportMIMEType, http.StatusOK)
	default:
		reqLog.Error("Unexpected scan job status", slog.String("scan_job_status", scanJob.Status.String()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
	}
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	properties := map[string]string{
		propertyScannerType:  "os-package-vulnerability",
		propertyRegistryAuth: registryAuthorizationType,

		"org.label-schema.version":    h.info.Version,
		"org.label-schema.build-date": h.info.Date,
		"org.label-schema.vcs-ref":    h.info.Commit,
		"org.label-schema.vcs":        vcsURL,

		// Surfaced in Harbor's scanner detail view so an operator can see which
		// Clair this adapter is wired to, and how long a scan may take, without
		// reading the deployment. The URL is not a secret; the PSK is, and only
		// whether one is configured is ever reported.
		"env.SCANNER_CLAIR_URL":           h.config.Clair.URL,
		"env.SCANNER_CLAIR_INDEX_TIMEOUT": h.config.Clair.IndexTimeout.String(),
		"env.SCANNER_CLAIR_PSK_ENABLED":   strconv.FormatBool(h.config.Clair.IsPSKEnabled()),
	}

	if h.vulnDBUpdatedAt != nil {
		// Omitted rather than reported as a zero time when Clair cannot answer:
		// a 1970 timestamp in the Harbor UI reads as a stale database.
		if updatedAt, ok := h.vulnDBUpdatedAt(req.Context()); ok {
			properties[propertyVulnDBUpdated] = updatedAt.UTC().Format(time.RFC3339)
		}
	}

	metadata := &harbor.ScannerAdapterMetadata{
		Scanner: h.scanner,
		Capabilities: []harbor.Capability{
			{
				Type: harbor.CapabilityTypeVulnerability,
				// Index media types are deliberately absent. Harbor tests the
				// artifact's manifest media type against this list, finds an
				// index unsupported, and fans out to the child manifests itself,
				// one scan job per child.
				ConsumesMIMETypes: []string{
					api.MimeTypeDockerImageManifestV2.String(),
					api.MimeTypeOCIImageManifest.String(),
				},
				ProducesMIMETypes: []string{
					api.MimeTypeSecurityVulnerabilityReport.String(),
				},
			},
		},
		Properties: properties,
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	if h.ready != nil {
		if err := h.ready(req.Context()); err != nil {
			slog.Debug("Not ready", slog.String("err", err.Error()))
			res.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	res.WriteHeader(http.StatusOK)
}
