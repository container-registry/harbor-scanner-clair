// Package clair is the client for the Clair v4 indexer and matcher API.
//
// Clair v4 inverts the adapter model of Clair 2.x. Instead of pushing layer
// bytes, the adapter posts one manifest describing where the layers live and
// which headers fetch them; Clair pulls the blobs itself, indexes them
// synchronously, and computes the vulnerability report on demand from data it
// keeps up to date on its own schedule. The adapter therefore never touches
// Clair's database, and nothing here resembles the old layer chain.
//
// The wire structs are the adapter's own. Importing claircore would drag pgx,
// grpc, a dozen OpenTelemetry modules and rabbitmq into go.sum for six structs
// whose shape is twenty lines, and claircore.Layer carries a noCopy field plus
// a mandatory Init() that makes literals illegal. The structs here are pinned
// by fixture tests against JSON captured from a real Clair 4.9.0 instead.
package clair

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	indexReportPath         = "/indexer/api/v1/index_report"
	indexStatePath          = "/indexer/api/v1/index_state"
	vulnerabilityReportPath = "/matcher/api/v1/vulnerability_report/"
	updateOperationPath     = "/matcher/api/v1/internal/update_operation?latest=true&kind=vulnerability"
)

// readinessDigest is a well-formed digest that can never name an indexed
// manifest, so the matcher answers it from its own state alone: 202 while it
// has never finished an update, 404 once it has.
const readinessDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

const (
	// maxReportBytes bounds a decoded report. A vulnerability report for a
	// large image runs to megabytes; this is the point past which the body is
	// no longer plausible.
	maxReportBytes = 64 << 20
	// maxErrorBytes bounds how much of an error response is copied into a Go
	// error. That text ends up in Harbor's scan job failure message.
	maxErrorBytes = 4096
)

// The retry policy, shared by the two calls that can legitimately be told to
// come back later. Intervals are constants rather than settings: an operator
// tuning them cannot make Clair answer sooner, and the budgets that do matter
// (the index timeout and the report retry timeout) are configurable.
const (
	retryInitialInterval = 2 * time.Second
	retryMaxInterval     = 30 * time.Second
	retryFactor          = 2
	// reportNotFoundAttempts is how often a 404 is retried before it is taken
	// at face value. The indexer commits the report before the POST returns, so
	// a 404 after a successful index is a replication or cache artifact, not a
	// state worth waiting minutes for.
	reportNotFoundAttempts = 3
)

// Defaults for a Config left zero. They are the plan's values; SCANNER_CLAIR_*
// overrides arrive with the configuration rewrite.
const (
	defaultIndexTimeout       = 10 * time.Minute
	defaultRequestTimeout     = 30 * time.Second
	defaultReportRetryTimeout = 5 * time.Minute
)

// vulnDBCacheTTL bounds how often the vulnerability-database timestamp is
// re-read. Harbor's UI calls /api/v1/metadata on every scanner page load, and
// the value moves at most once per updater period.
const vulnDBCacheTTL = 10 * time.Minute

// Sentinel errors. The scan path branches on these with errors.Is to pick the
// category it reports to Harbor, so they are part of this package's contract.
var (
	// ErrIndexFailed means Clair accepted the manifest and could not index it.
	ErrIndexFailed = errors.New("clair failed to index the artifact")
	// ErrUnauthorized means the PSK token was missing, wrong, or issued by an
	// issuer Clair does not allow.
	ErrUnauthorized = errors.New("clair rejected the adapter's credentials")
	// ErrBadRequest means Clair will not accept this request however often it
	// is repeated.
	ErrBadRequest = errors.New("clair rejected the request")
	// ErrUnscannableLayer means a layer is not a filesystem Clair can read.
	ErrUnscannableLayer = errors.New("clair cannot read a layer of this artifact")
	// ErrMatcherNotReady means the matcher has never finished an update, so it
	// has no vulnerability data to match against yet.
	ErrMatcherNotReady = errors.New("clair's matcher is not initialized")
	// ErrNotIndexed means the matcher has no finished index report for the
	// manifest.
	ErrNotIndexed = errors.New("clair has no index report for the artifact")
	// ErrRateLimited means Clair is at its request concurrency limit.
	ErrRateLimited = errors.New("clair is rate limiting the adapter")
	// ErrServerError is a server-side failure inside Clair.
	ErrServerError = errors.New("clair returned a server error")
	// ErrReportTruncated means the body did not decode as a complete report, or
	// Clair set the Clair-Error trailer after a body that did decode.
	ErrReportTruncated = errors.New("clair truncated the vulnerability report")
)

// Config is the Clair connection.
type Config struct {
	// URL is the API root, e.g. http://clair:6060.
	URL string
	// PSK is the pre-shared key, base64-encoded exactly as it appears in
	// Clair's auth.psk.key. Empty means Clair runs without authentication and
	// no Authorization header is sent at all.
	PSK string
	// Issuer is the JWT iss claim. It must appear in Clair's auth.psk.iss.
	Issuer string
	// IndexTimeout bounds the synchronous index call, blob fetches included.
	IndexTimeout time.Duration
	// RequestTimeout bounds every other single call.
	RequestTimeout time.Duration
	// ReportRetryTimeout is the budget for the whole 202/404/429 report loop.
	ReportRetryTimeout time.Duration
}

type Client interface {
	// Index submits a manifest and blocks until Clair finishes indexing it.
	Index(ctx context.Context, m Manifest) (*IndexReport, error)
	// VulnerabilityReport fetches the matcher's report for an indexed manifest.
	VulnerabilityReport(ctx context.Context, manifestHash string) (*VulnerabilityReport, error)
	// IndexState is the indexer's liveness and configuration token.
	IndexState(ctx context.Context) (string, error)
	// MatcherReady reports whether the matcher has vulnerability data. It is
	// narrower than it sounds: Clair answers from SELECT EXISTS(SELECT 1 FROM
	// vuln), so it flips as soon as one updater has committed rows, says
	// nothing about enrichment, and never goes back to false.
	MatcherReady(ctx context.Context) (bool, error)
	// VulnDBUpdatedAt is the newest vulnerability update_operation date. ok is
	// false when the value could not be determined, and the caller then omits
	// the metadata property rather than reporting a zero time.
	VulnDBUpdatedAt(ctx context.Context) (t time.Time, ok bool, err error)
}

type client struct {
	baseURL string
	http    *http.Client
	signer  *signer

	indexTimeout       time.Duration
	requestTimeout     time.Duration
	reportRetryTimeout time.Duration

	// Backoff bounds, overridden in tests to keep sleeps short.
	retryInitial time.Duration
	retryMax     time.Duration

	mu              sync.Mutex
	vulnDBAt        time.Time
	vulnDBOK        bool
	vulnDBFetchedAt time.Time
}

// NewClient builds the Clair client. tlsConfig is the adapter's outbound trust
// configuration and may be nil.
func NewClient(cfg Config, tlsConfig *tls.Config) (Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("clair URL must not be empty")
	}

	var psk *signer
	if cfg.PSK != "" {
		if cfg.Issuer == "" {
			return nil, errors.New("a Clair PSK is configured without an issuer: set SCANNER_CLAIR_JWT_ISSUER to a value listed in Clair's auth.psk.iss")
		}
		var err error
		if psk, err = newSigner(cfg.PSK, cfg.Issuer); err != nil {
			return nil, err
		}
	}

	// A cloned DefaultTransport keeps the connection pooling and proxy support
	// a bare &http.Transport{} silently drops.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &client{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		// Timeout stays unset: the index call and the report call need very
		// different bounds, and a client-level timeout cannot vary per call.
		// Every call sets its own context deadline instead.
		http:               &http.Client{Transport: transport},
		signer:             psk,
		indexTimeout:       orDefault(cfg.IndexTimeout, defaultIndexTimeout),
		requestTimeout:     orDefault(cfg.RequestTimeout, defaultRequestTimeout),
		reportRetryTimeout: orDefault(cfg.ReportRetryTimeout, defaultReportRetryTimeout),
		retryInitial:       retryInitialInterval,
		retryMax:           retryMaxInterval,
	}, nil
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

func (c *client) Index(ctx context.Context, m Manifest) (*IndexReport, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling index request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.indexTimeout)
	defer cancel()

	var report *IndexReport
	err = c.withRetry(ctx, func(attemptCtx context.Context) error {
		var attemptErr error
		report, attemptErr = c.indexAttempt(attemptCtx, m.Hash, body)
		return attemptErr
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

func (c *client) indexAttempt(ctx context.Context, manifestHash string, body []byte) (*IndexReport, error) {
	resp, err := c.do(ctx, http.MethodPost, indexReportPath, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusCreated:
		var report IndexReport
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxReportBytes)).Decode(&report); err != nil {
			return nil, fmt.Errorf("decoding index report: %w", err)
		}
		if report.State != StateIndexFinished || !report.Success {
			return nil, fmt.Errorf("%w: state %q: %s", ErrIndexFailed, report.State, report.Err)
		}
		return &report, nil
	case http.StatusBadRequest:
		detail := readErrorBody(resp)
		// tarfs.ErrFormat is what Clair reports when a layer is not a tar it
		// can walk, which is the signature or attestation case rather than a
		// broken request.
		if strings.Contains(detail, "tarfs") || strings.Contains(detail, "format") {
			return nil, fmt.Errorf("%w: %s", ErrUnscannableLayer, detail)
		}
		return nil, fmt.Errorf("%w: clair rejected the manifest: %s", ErrBadRequest, detail)
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, unauthorizedError(resp)
	case http.StatusPreconditionFailed:
		// Unreachable: the adapter never sends If-None-Match. Defensively, a
		// 412 means the indexer's state already matches, so the manifest is
		// indexed and the report is the next call.
		return &IndexReport{ManifestHash: manifestHash, State: StateIndexFinished, Success: true}, nil
	default:
		return nil, c.statusError(resp, "indexing the artifact")
	}
}

func (c *client) VulnerabilityReport(ctx context.Context, manifestHash string) (*VulnerabilityReport, error) {
	ctx, cancel := context.WithTimeout(ctx, c.reportRetryTimeout)
	defer cancel()

	var (
		report   *VulnerabilityReport
		notFound int
	)
	err := c.withRetry(ctx, func(attemptCtx context.Context) error {
		reqCtx, reqCancel := context.WithTimeout(attemptCtx, c.requestTimeout)
		defer reqCancel()

		var attemptErr error
		report, attemptErr = c.reportAttempt(reqCtx, manifestHash, &notFound)
		return attemptErr
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

func (c *client) reportAttempt(ctx context.Context, manifestHash string, notFound *int) (*VulnerabilityReport, error) {
	resp, err := c.do(ctx, http.MethodGet, vulnerabilityReportPath+manifestHash, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// The status is 200 although the spec says 201: the handler never calls
		// WriteHeader. Do not gate on the content type either, 4.9.0 labels the
		// vulnerability report application/vnd.clair.index_report.v1+json.
		var report VulnerabilityReport
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxReportBytes)).Decode(&report); err != nil {
			// Clair sets Clair-Error when its encoder fails mid-stream, which
			// leaves a partial body: the decode fails before the trailer is ever
			// read, so the decode error is the truncation signal.
			return nil, fmt.Errorf("%w: decoding vulnerability report: %w", ErrReportTruncated, err)
		}
		// Go populates resp.Trailer only once the body has been read to EOF, so
		// draining is what makes the trailer check work at all. A client that
		// checks the status alone silently accepts a truncated report.
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return nil, fmt.Errorf("reading the vulnerability report to completion: %w", err)
		}
		if detail := resp.Trailer.Get("Clair-Error"); detail != "" {
			return nil, fmt.Errorf("%w: %s", ErrReportTruncated, detail)
		}
		return &report, nil
	case http.StatusAccepted:
		// The matcher has never finished an update, so it has nothing to match
		// against. Worth waiting for: it is a fresh deployment, not a fault.
		return nil, &retryableError{
			err:   fmt.Errorf("%w: it is still loading its first vulnerability data", ErrMatcherNotReady),
			after: c.retryAfter(resp),
		}
	case http.StatusNotFound:
		*notFound++
		if *notFound >= reportNotFoundAttempts {
			return nil, fmt.Errorf("%w: %s", ErrNotIndexed, manifestHash)
		}
		return nil, &retryableError{
			err:   fmt.Errorf("%w: %s", ErrNotIndexed, manifestHash),
			after: c.retryAfter(resp),
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, unauthorizedError(resp)
	default:
		return nil, c.statusError(resp, "fetching the vulnerability report")
	}
}

func (c *client) IndexState(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	resp, err := c.do(ctx, http.MethodGet, indexStatePath, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var state struct {
			State string `json:"state"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBytes)).Decode(&state); err != nil {
			return "", fmt.Errorf("decoding index state: %w", err)
		}
		return state.State, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", unauthorizedError(resp)
	default:
		return "", c.statusError(resp, "reading the indexer state")
	}
}

func (c *client) MatcherReady(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	resp, err := c.do(ctx, http.MethodGet, vulnerabilityReportPath+readinessDigest, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusAccepted:
		return false, nil
	case http.StatusNotFound:
		// The matcher got as far as looking the manifest up, which it only does
		// once it considers itself initialized.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, unauthorizedError(resp)
	default:
		return false, c.statusError(resp, "probing the matcher")
	}
}

func (c *client) VulnDBUpdatedAt(ctx context.Context) (time.Time, bool, error) {
	c.mu.Lock()
	cached, cachedOK, fresh := c.vulnDBAt, c.vulnDBOK, time.Since(c.vulnDBFetchedAt) < vulnDBCacheTTL
	c.mu.Unlock()
	if cachedOK && fresh {
		return cached, true, nil
	}

	latest, err := c.fetchVulnDBUpdatedAt(ctx)
	if err != nil {
		// update_operation is documented as internal and "may not exist" in
		// combo mode, so a failure here is not an adapter fault: the metadata
		// property is dropped and the last good value keeps being served.
		slog.Debug("Could not read Clair's latest vulnerability update operation",
			slog.String("err", err.Error()))
		if cachedOK {
			return cached, true, nil
		}
		return time.Time{}, false, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.vulnDBAt, c.vulnDBOK, c.vulnDBFetchedAt = latest, true, time.Now()
	return latest, true, nil
}

func (c *client) fetchVulnDBUpdatedAt(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	resp, err := c.do(ctx, http.MethodGet, updateOperationPath, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, c.statusError(resp, "reading the latest update operation")
	}

	var operations map[string][]updateOperation
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReportBytes)).Decode(&operations); err != nil {
		return time.Time{}, fmt.Errorf("decoding update operations: %w", err)
	}

	var latest time.Time
	for _, ops := range operations {
		for _, op := range ops {
			if op.Date.After(latest) {
				latest = op.Date
			}
		}
	}
	if latest.IsZero() {
		return time.Time{}, errors.New("clair reported no vulnerability update operation")
	}
	return latest, nil
}

func (c *client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("building clair request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.signer != nil {
		// Signed per request: one HMAC-SHA256 over ~200 bytes is not worth a
		// cache, and a cached token is one more thing that can expire mid-scan.
		token, signErr := c.signer.sign(time.Now())
		if signErr != nil {
			return nil, signErr
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling clair %s: %w", method+" "+path, err)
	}
	return resp, nil
}

// retryableError marks a failure worth repeating, carrying the server's
// Retry-After hint when it sent a usable one.
type retryableError struct {
	err   error
	after time.Duration
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// withRetry runs attempt until it succeeds, fails permanently, or the context
// budget is spent. The budget belongs to the caller: it is the per-call timeout
// and, above it, the per-job deadline, so no loop can outlive the job lock.
func (c *client) withRetry(ctx context.Context, attempt func(context.Context) error) error {
	interval := c.retryInitial
	var last error
	for {
		err := attempt(ctx)
		var retryable *retryableError
		if !errors.As(err, &retryable) {
			// The budget can expire inside an attempt rather than in the sleep;
			// the caller still needs the reason we were retrying, not a bare
			// context error.
			if ctx.Err() != nil && last != nil {
				return fmt.Errorf("gave up waiting for clair: %w (%v)", last, err)
			}
			return err
		}
		last = retryable.err

		delay := jitter(interval)
		if retryable.after > 0 {
			delay = retryable.after
		}
		if waitErr := sleep(ctx, delay); waitErr != nil {
			return fmt.Errorf("gave up waiting for clair: %w", retryable.err)
		}
		if interval < c.retryMax {
			interval = min(interval*retryFactor, c.retryMax)
		}
	}
}

// jitter spreads a retry over the second half of the interval, so concurrent
// workers that were rate limited together do not come back together.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryAfter honors the server's hint when it is a plain number of seconds no
// longer than the computed backoff would ever be. A longer or unparseable value
// is ignored, because a proxy that answers "Retry-After: 3600" must not park a
// scan job for an hour.
func (c *client) retryAfter(resp *http.Response) time.Duration {
	value := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0
	}
	if d := time.Duration(seconds) * time.Second; d <= c.retryMax {
		return d
	}
	return 0
}

// statusError maps the statuses that are not part of a call's own ladder.
// 502/503/504 and 429 are worth repeating; everything else, 500 included, is
// taken as final.
func (c *client) statusError(resp *http.Response, action string) error {
	detail := readErrorBody(resp)
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return &retryableError{
			err:   fmt.Errorf("%w while %s: %s", ErrRateLimited, action, detail),
			after: c.retryAfter(resp),
		}
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &retryableError{
			err:   fmt.Errorf("%w while %s (%s): %s", ErrServerError, action, resp.Status, detail),
			after: c.retryAfter(resp),
		}
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("%w while %s (%s): %s", ErrServerError, action, resp.Status, detail)
	}
	return fmt.Errorf("%w while %s (%s): %s", ErrBadRequest, action, resp.Status, detail)
}

func unauthorizedError(resp *http.Response) error {
	return fmt.Errorf("%w (%s): check SCANNER_CLAIR_PSK, and that SCANNER_CLAIR_JWT_ISSUER is listed in Clair's auth.psk.iss: %s",
		ErrUnauthorized, resp.Status, readErrorBody(resp))
}

func readErrorBody(resp *http.Response) string {
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
	return strings.TrimSpace(string(detail))
}
