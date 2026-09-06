package persistence

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bigReport is deliberately repetitive, like a real vulnerability report:
// hundreds of items differing only in package name, version and CVE id.
func bigReport(items int) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteString(`{"generated_at":"2026-09-05T00:00:00Z","severity":"High","vulnerabilities":[`)
	for i := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"id":"CVE-2026-%04d","package":"libexample-%d","version":"1.2.%d","fix_version":"1.2.%d","severity":"High","description":"An example vulnerability in libexample","links":["https://example.test/CVE-2026-%04d"]}`,
			i, i, i, i+1, i)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

// TestReportRoundTrips is the baseline: what the store writes is what a report
// poll reads back, byte for byte.
func TestReportRoundTrips(t *testing.T) {
	report := bigReport(200)

	stored, err := EncodeReport(report)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(stored, gzipMagic), "report must be stored gzipped")

	got, err := DecodeReport(stored)
	require.NoError(t, err)
	assert.JSONEq(t, string(report), string(got))
}

// TestReportIsCompressed measures the saving rather than asserting compression
// happened. A vulnerability report is repetitive JSON, so the ratio is the
// whole point: this is what the table holds for the scan job TTL and re-reads
// on every Harbor poll.
func TestReportIsCompressed(t *testing.T) {
	report := bigReport(2000)

	stored, err := EncodeReport(report)
	require.NoError(t, err)

	t.Logf("raw=%d bytes stored=%d bytes ratio=%.1fx", len(report), len(stored), float64(len(report))/float64(len(stored)))
	assert.Less(t, len(stored), len(report)/4, "a repetitive report must compress by at least 4x")
}

// TestEmptyReportEncodesToNothing pins the NULL column: a job that has not
// finished has no report, and gzipping nothing would store 20-odd bytes that
// then decode to an empty document instead of "no report".
func TestEmptyReportEncodesToNothing(t *testing.T) {
	stored, err := EncodeReport(nil)
	require.NoError(t, err)
	assert.Empty(t, stored)

	got, err := DecodeReport(nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestDecodeReadsPlaintext keeps the decoder tolerant of an uncompressed value:
// sniffing the magic costs two bytes and turns a hand-written or older-format
// row into a readable report rather than a 500 on every poll.
func TestDecodeReadsPlaintext(t *testing.T) {
	plaintext := json.RawMessage(`{"severity":"None"}`)
	got, err := DecodeReport(plaintext)
	require.NoError(t, err)
	assert.JSONEq(t, string(plaintext), string(got))
}

// TestDecodeRejectsADecompressionBomb bounds what one report may expand to on a
// poll. Report content derives from a scanned image, so it is
// attacker-influenced, and gzip on repetitive JSON reaches ratios in the tens:
// a small stored value can otherwise turn into a large allocation on every poll.
func TestDecodeRejectsADecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// Highly compressible, well past the limit.
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for written := 0; written <= maxReportBytes; written += len(chunk) {
		_, err := zw.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.Less(t, buf.Len(), 1<<20, "the bomb must be small on the wire, or it is not a bomb")

	_, err := DecodeReport(buf.Bytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expands beyond")
}

// TestEncodeRejectsAnOversizeReport keeps the bound symmetric: without it an
// oversize report would be written successfully and then be unreadable, failing
// at poll time instead of at scan time.
func TestEncodeRejectsAnOversizeReport(t *testing.T) {
	_, err := EncodeReport(json.RawMessage(`"` + strings.Repeat("x", maxReportBytes+16) + `"`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "over the")
}
