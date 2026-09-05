package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/etc"
	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/pkg/http/api"
	"github.com/container-registry/harbor-scanner-clair/pkg/job"
	"github.com/container-registry/harbor-scanner-clair/pkg/persistence"
	"github.com/container-registry/harbor-scanner-clair/pkg/queue"
)

const (
	pathVarScanRequestID = "scan_request_id"

	// refreshAfter is the report poll hint. Harbor parses Refresh-After with
	// ParseInt(v, 10, 8), so it MUST be <= 127. 5 seconds.
	refreshAfter = "5"
)

// ReadyFunc reports whether the adapter can serve scans. A non-nil error
// answers /probe/ready with 503.
type ReadyFunc func(ctx context.Context) error

type requestHandler struct {
	clair    clair.Client
	enqueuer queue.Enqueuer
	store    persistence.Store
	ready    ReadyFunc
	api.BaseHandler
}

func NewAPIHandler(clairClient clair.Client, enqueuer queue.Enqueuer, store persistence.Store, ready ReadyFunc) http.Handler {
	handler := &requestHandler{
		clair:    clairClient,
		enqueuer: enqueuer,
		store:    store,
		ready:    ready,
	}
	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.GetMetadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.AcceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.GetScanReport)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.GetHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.GetReady)

	router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())
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

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		slog.Error("Error while unmarshalling scan request", slog.String("err", err.Error()))
		h.WriteJSONError(res, harbor.Error{
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
		slog.Error("Error while performing scan", slog.String("err", err.Error()))
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("performing scan: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, harbor.ScanResponse{ID: jobID}, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) validate(req harbor.ScanRequest) *harbor.Error {
	if req.Registry.URL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	_, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	jobID, ok := vars[pathVarScanRequestID]
	if !ok {
		slog.Error("Error while parsing `scan_request_id` path variable")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan_request_id",
		})
		return
	}

	reqLog := slog.With(slog.String("scan_job_id", jobID))

	scanJob, err := h.store.Get(req.Context(), jobID)
	if err != nil {
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}

	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, harbor.Error{
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
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
	case job.Finished:
		h.WriteJSON(res, scanJob.Report, api.MimeTypeScanReport, http.StatusOK)
	default:
		reqLog.Error("Unexpected scan job status", slog.String("scan_job_status", scanJob.Status.String()))
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
	}
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, _ *http.Request) {
	properties := map[string]string{
		"harbor.scanner-adapter/scanner-type":                "os-package-vulnerability",
		"harbor.scanner-adapter/registry-authorization-type": "Bearer",
	}

	updatedAt, err := h.clair.GetVulnerabilityDatabaseUpdatedAt()
	if err != nil {
		slog.Error("Failed to get vulnerability database updated time", slog.String("err", err.Error()))
	} else if updatedAt != nil {
		properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = updatedAt.Format(time.RFC3339)
	}

	metadata := &harbor.ScannerMetadata{
		Scanner: etc.GetScannerMetadata(),
		Capabilities: []harbor.Capability{
			{
				ConsumesMimeTypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerDistributionManifest.String(),
				},
				ProducesMimeTypes: []string{
					api.MimeTypeScanReport.String(),
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
