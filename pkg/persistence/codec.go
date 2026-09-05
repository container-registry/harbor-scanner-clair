package persistence

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/container-registry/harbor-scanner-clair/pkg/metrics"
)

// The report is stored gzipped because it is almost entirely the vulnerability
// report, which is highly repetitive JSON: the same package names, severities
// and link hosts repeat once per finding. The column holding it is bytea, so
// the compressed bytes go in as-is.
//
// DecodeReport sniffs the gzip magic instead of assuming, so a row holding a
// plaintext report is still readable rather than a hard failure.
var gzipMagic = []byte{0x1f, 0x8b}

// maxReportBytes bounds what one stored report may expand to. gzip on
// repetitive JSON reaches ratios in the tens, so a small column value can
// expand into a large allocation on every report poll. The report content is
// derived from a scanned image, which is attacker-influenced. 64 MiB is orders
// of magnitude above any real vulnerability report and is a bomb guard, not a
// working limit. Enforced on write too, so an oversized report fails at scan
// time with a clear cause instead of at poll time.
const maxReportBytes = 64 << 20

// EncodeReport compresses a marshaled report envelope for storage. An empty
// report encodes to no bytes at all: a job that has not finished has nothing to
// compress, and a NULL column is how the store recognizes that.
func EncodeReport(report json.RawMessage) ([]byte, error) {
	if len(report) == 0 {
		return nil, nil
	}
	if len(report) > maxReportBytes {
		return nil, fmt.Errorf("scan report is %d bytes, over the %d limit", len(report), maxReportBytes)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(report); err != nil {
		return nil, fmt.Errorf("compressing scan report: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compressing scan report: %w", err)
	}

	metrics.ReportBytes.Observe(float64(buf.Len()))
	return buf.Bytes(), nil
}

// DecodeReport reverses EncodeReport.
func DecodeReport(stored []byte) (json.RawMessage, error) {
	if len(stored) == 0 {
		return nil, nil
	}
	if !bytes.HasPrefix(stored, gzipMagic) {
		return stored, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, fmt.Errorf("decompressing scan report: %w", err)
	}
	defer zr.Close()
	// Read one byte past the limit so hitting it is distinguishable from a
	// report that happens to be exactly maxReportBytes long.
	raw, err := io.ReadAll(io.LimitReader(zr, maxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompressing scan report: %w", err)
	}
	if len(raw) > maxReportBytes {
		return nil, fmt.Errorf("stored scan report expands beyond the %d byte limit", maxReportBytes)
	}
	return raw, nil
}
