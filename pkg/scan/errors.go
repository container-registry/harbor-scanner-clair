package scan

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
)

// Category classifies a scan failure. The value is both the prefix of the
// error string stored on the job, which is what Harbor renders as the scan
// job's failure detail, and the category label on
// harbor_scanner_clair_scans_total. One vocabulary for both means an operator
// who sees [auth] in the UI and an operator who sees category="auth" on a
// dashboard take the same next step.
type Category string

const (
	// CategoryManifest is a registry manifest that could not be fetched or parsed.
	CategoryManifest Category = "manifest"
	// CategoryAuth is a 401 or 403 from the registry or from Clair.
	CategoryAuth Category = "auth"
	// CategoryUnscannable is an artifact Clair cannot index: an index, zero
	// layers, or a layer that is not a tarball.
	CategoryUnscannable Category = "unscannable_layer"
	// CategoryClairRequest is an unexpected Clair status or an undecodable body.
	CategoryClairRequest Category = "clair_request"
	// CategoryClairIndex is an IndexError, a report that is not successful, or a
	// 404 that survived a good index.
	CategoryClairIndex Category = "clair_index"
	// CategoryClairUnavailable is a 202, 429 or 5xx that outlived the retry budget.
	CategoryClairUnavailable Category = "clair_unavailable"
	// CategoryNetwork is a transport error reaching the registry or Clair.
	CategoryNetwork Category = "network"
	// CategoryTimeout is the job deadline or a per-call deadline firing.
	CategoryTimeout Category = "timeout"
	// CategoryReportParse is a report that did not decode or arrived truncated.
	CategoryReportParse Category = "report_parse"
	// CategoryAdapter is the adapter's own bug. Anything uncategorised lands
	// here, so a spike in it is a signal to add a category, not to blame Clair.
	CategoryAdapter Category = "adapter"
)

// Error is a scan failure with the category already decided. Detail says what
// the adapter was doing, Cause is the wrapped error.
type Error struct {
	Category Category
	Detail   string
	Cause    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s: %v", e.Category, e.Detail, e.Cause)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// Categorize maps any error raised on the scan path onto a Category. An error
// that already carries one keeps it; otherwise the sentinels the Clair client
// wraps decide, then the context and transport errors underneath them.
func Categorize(err error) Category {
	if err == nil {
		return ""
	}

	var scanErr *Error
	if errors.As(err, &scanErr) {
		return scanErr.Category
	}

	switch {
	case errors.Is(err, clair.ErrUnauthorized):
		return CategoryAuth
	case errors.Is(err, clair.ErrUnscannableLayer):
		return CategoryUnscannable
	case errors.Is(err, clair.ErrIndexFailed), errors.Is(err, clair.ErrNotIndexed):
		return CategoryClairIndex
	case errors.Is(err, clair.ErrMatcherNotReady),
		errors.Is(err, clair.ErrRateLimited),
		errors.Is(err, clair.ErrServerError):
		return CategoryClairUnavailable
	case errors.Is(err, clair.ErrBadRequest):
		return CategoryClairRequest
	case errors.Is(err, clair.ErrReportTruncated):
		return CategoryReportParse
	// The per-job deadline in the queue surfaces as DeadlineExceeded, a worker
	// shutting down surfaces as Canceled. Both mean the job ran out of time,
	// which is not an adapter bug.
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return CategoryTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return CategoryTimeout
		}
		return CategoryNetwork
	}

	return CategoryAdapter
}
