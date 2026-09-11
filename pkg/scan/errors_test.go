package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/clair"
	"github.com/container-registry/harbor-scanner-clair/pkg/registry"
)

func TestError(t *testing.T) {
	cause := errors.New("connection refused")
	err := &Error{Category: CategoryClairUnavailable, Detail: "getting the vulnerability report", Cause: cause}

	// The string is what Harbor renders as the scan job's failure detail.
	assert.Equal(t, "[clair_unavailable] getting the vulnerability report: connection refused", err.Error())
	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestCategorize(t *testing.T) {
	timeoutErr := &net.DNSError{Err: "i/o timeout", Name: "clair", IsTimeout: true}
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}

	tests := []struct {
		name string
		err  error
		want Category
	}{
		{name: "no error has no category", err: nil, want: ""},
		{
			name: "an error that already carries a category keeps it",
			err:  fmt.Errorf("scanning: %w", &Error{Category: CategoryManifest, Detail: "getting the manifest", Cause: errors.New("404")}),
			want: CategoryManifest,
		},
		{name: "the registry rejects the scan token", err: fmt.Errorf("getting the manifest: %w", registry.ErrRegistryAuth), want: CategoryAuth},
		{name: "no manifest", err: fmt.Errorf("getting the manifest: %w", registry.ErrManifestNotFound), want: CategoryManifest},
		{name: "the manifest could not be fetched", err: fmt.Errorf("getting the manifest: %w", registry.ErrManifestFetch), want: CategoryManifest},
		{name: "an index or a zero-layer artifact", err: fmt.Errorf("getting the manifest: %w", registry.ErrUnsupportedArtifact), want: CategoryUnscannable},
		{name: "a layer that is not a tarball", err: fmt.Errorf("getting the manifest: %w", registry.ErrUnscannableLayer), want: CategoryUnscannable},
		{name: "unauthorized", err: fmt.Errorf("indexing: %w", clair.ErrUnauthorized), want: CategoryAuth},
		{name: "unscannable layer", err: fmt.Errorf("indexing: %w", clair.ErrUnscannableLayer), want: CategoryUnscannable},
		{name: "index failed", err: fmt.Errorf("indexing: %w", clair.ErrIndexFailed), want: CategoryClairIndex},
		{name: "not indexed", err: fmt.Errorf("getting the report: %w", clair.ErrNotIndexed), want: CategoryClairIndex},
		{name: "matcher not ready", err: fmt.Errorf("getting the report: %w", clair.ErrMatcherNotReady), want: CategoryClairUnavailable},
		{name: "rate limited", err: fmt.Errorf("indexing: %w", clair.ErrRateLimited), want: CategoryClairUnavailable},
		{name: "server error", err: fmt.Errorf("indexing: %w", clair.ErrServerError), want: CategoryClairUnavailable},
		{name: "bad request", err: fmt.Errorf("indexing: %w", clair.ErrBadRequest), want: CategoryClairRequest},
		{name: "truncated report", err: fmt.Errorf("getting the report: %w", clair.ErrReportTruncated), want: CategoryReportParse},
		{name: "the job deadline", err: fmt.Errorf("indexing: %w", context.DeadlineExceeded), want: CategoryTimeout},
		{name: "a worker shutting down", err: fmt.Errorf("indexing: %w", context.Canceled), want: CategoryTimeout},
		{name: "a transport timeout", err: &url.Error{Op: "Post", URL: "http://clair:6060", Err: timeoutErr}, want: CategoryTimeout},
		{name: "a transport failure", err: &url.Error{Op: "Post", URL: "http://clair:6060", Err: dialErr}, want: CategoryNetwork},
		{name: "anything else is the adapter's own fault", err: errors.New("nil map"), want: CategoryAdapter},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Categorize(tc.err))
		})
	}
}

// TestCategorizePrefersTheOuterCategory pins the precedence: a wrapped sentinel
// does not override a category the scan path has already decided.
func TestCategorizePrefersTheOuterCategory(t *testing.T) {
	err := &Error{
		Category: CategoryClairIndex,
		Detail:   "indexing the artifact",
		Cause:    fmt.Errorf("posting the index report: %w", clair.ErrServerError),
	}

	require.True(t, errors.Is(err, clair.ErrServerError))
	assert.Equal(t, CategoryClairIndex, Categorize(err))
}
