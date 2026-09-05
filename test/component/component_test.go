//go:build component

// Package component drives the adapter end to end against a real Clair 4.x, a
// real registry and a real image. Everything it talks to is brought up by
// docker-compose.yml in this directory; nothing here is faked.
//
// Run it with `task compose:up && task test:component`. Pass -update-fixtures
// to rewrite pkg/clair/testdata/vulnerability_report_alpine310.json from what
// this Clair actually produced, which is what keeps the unit fixtures honest.
package component

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
	"github.com/container-registry/harbor-scanner-clair/test/contract/harborcontract"
)

// Endpoints, matching the published ports in docker-compose.yml. adapterURL and
// registryURL are the host's view; registryInNetwork is the same registry as
// Clair and the adapter see it, and it is what goes into the scan request,
// because Clair fetches every layer itself from the URL the adapter builds.
const (
	adapterURL        = "http://localhost:18080"
	clairURL          = "http://localhost:16060"
	registryURL       = "http://localhost:15000"
	registryInNetwork = "http://registry:5000"
)

// The seeded artifact. alpine 3.10 is end of life, so it reliably has findings,
// and the compose seed pins it to linux/amd64 so the digest does not depend on
// the host.
const (
	seededRepository = "library/alpine"
	seededTag        = "3.10"
)

// The PSK in clair/config.yaml. A throwaway key committed on purpose: it
// authenticates nothing but this compose stack. The test signs its own tokens
// rather than reusing pkg/clair's unexported signer, so the direct Clair calls
// here stay independent of the code under test. Clair without an auth block
// ignores the header, which is why signing unconditionally is safe.
const (
	componentPSK    = "Q9CT6HPYgE8EW7ulY/MJfonJdMxSbrbKJVhY8GsVAzc="
	componentIssuer = "harbor-scanner-clair"
)

// zeroDigest is well formed and can never name an indexed manifest, so the
// matcher answers it from its own state alone: 202 while it has never finished
// an update, 404 once the vuln table is non-empty.
const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

const (
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerConfig   = "application/vnd.docker.container.image.v1+json"
	mediaTypeReport         = "application/vnd.security.vulnerability.report; version=1.1"
	// mediaTypeCosignPayload is the layer type cosign gives a signature. It is
	// JSON, not a tarball, so no indexer can read it.
	mediaTypeCosignPayload = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// defaultReadyTimeout caps the wait for the matcher. Measured on a laptop the
// first update answers in 16s and completes in 85s, but the CVSS enricher walks
// the NVD feeds from 2002 and a cold cache or a slow mirror makes that number
// worthless as a bound.
const defaultReadyTimeout = 20 * time.Minute

// reportPollTimeout bounds one scan. Indexing alpine 3.10 from an in-network
// registry took 0.10s when measured; this is the point past which something is
// wrong rather than slow.
const reportPollTimeout = 5 * time.Minute

var updateFixtures = flag.Bool("update-fixtures", false,
	"rewrite pkg/clair/testdata/vulnerability_report_alpine310.json from this Clair's output")

// client never follows a redirect. The report endpoint answers 302 with a
// Location pointing back at itself while the job runs, so a following client
// spins until net/http gives up after ten hops and the 302 contract goes
// untested.
var client = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Timeout:       30 * time.Second,
}

// seededDigest is the manifest digest resolved from the registry in TestMain.
var seededDigest string

func TestMain(m *testing.M) {
	flag.Parse()

	if err := waitForAdapter(); err != nil {
		log.Fatalf("adapter is not serving: %v", err)
	}
	if err := waitForMatcher(); err != nil {
		log.Fatalf("clair's matcher never became ready: %v", err)
	}

	var err error
	if seededDigest, err = resolveDigest(seededRepository, seededTag); err != nil {
		log.Fatalf("resolving the seeded artifact: %v", err)
	}
	log.Printf("seeded artifact %s:%s is %s", seededRepository, seededTag, seededDigest)

	os.Exit(m.Run())
}

// TestMetadata proves the document Harbor reads on Test Connection is one
// Harbor accepts, using Harbor's own Validate() vendored under test/contract.
func TestMetadata(t *testing.T) {
	resp, body := get(t, adapterURL+"/api/v1/metadata", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)

	var metadata harborcontract.ScannerAdapterMetadata
	require.NoError(t, json.Unmarshal(body, &metadata))
	require.NoError(t, metadata.Validate(), "served metadata must pass Harbor's Validate()")

	require.Len(t, metadata.Capabilities, 1)
	assert.Equal(t, []string{mediaTypeReport}, metadata.Capabilities[0].ProducesMimeTypes)
	assert.Equal(t, "Bearer", metadata.Properties["harbor.scanner-adapter/registry-authorization-type"])

	// The timestamp comes from the matcher's update_operation endpoint. The
	// matcher is ready by now, so an update has committed and the property has
	// to be there and has to parse.
	updatedAt := metadata.Properties["harbor.scanner-adapter/vulnerability-database-updated-at"]
	require.NotEmpty(t, updatedAt, "vulnerability-database-updated-at is missing from %v", metadata.Properties)
	_, err := time.Parse(time.RFC3339, updatedAt)
	assert.NoError(t, err, "vulnerability-database-updated-at %q must be RFC3339", updatedAt)
}

// TestScanSeededArtifact is the whole scan path: accept, index, match,
// transform, serve. It also captures the Clair fixture the unit tests replay.
func TestScanSeededArtifact(t *testing.T) {
	report, redirects := scanUntilEnriched(t)

	require.NotEmpty(t, report.Vulnerabilities, "alpine 3.10 must produce findings")
	assert.Positive(t, redirects, "every report was ready before its first poll; the 302 ladder went untested")
	assert.Equal(t, seededDigest, report.Artifact.Digest)

	// Every severity has to be one of the seven Harbor names. A Severity that
	// did not decode renders as the empty string, and Harbor rejects the report.
	var highest harbor.Severity
	for _, item := range report.Vulnerabilities {
		assert.NotEmpty(t, item.Severity.String(), "vulnerability %s has an unnameable severity", item.ID)
		if item.Severity > highest {
			highest = item.Severity
		}
	}
	assert.Equal(t, highest, report.Severity, "report severity must be the maximum item severity")

	seen := map[string]bool{}
	for _, item := range report.Vulnerabilities {
		key := item.Pkg + "@" + item.Version + "/" + item.ID
		assert.False(t, seen[key], "duplicate vulnerability %s", key)
		seen[key] = true
	}

	// scanUntilEnriched has already established that CVSS arrives; this pins its
	// shape. alpine 3.10 yields one finding whose normalized_severity is Unknown
	// and whose CVSS 3.1 base score is 9.1, so it also exercises the fallback
	// that gives an Unknown finding a severity.
	for _, item := range report.Vulnerabilities {
		if item.PreferredCVSS == nil || item.PreferredCVSS.ScoreV3 == nil {
			continue
		}
		assert.True(t, strings.HasPrefix(item.PreferredCVSS.VectorV3, "CVSS:3."),
			"vector_v3 %q of %s is not a CVSS 3.x vector", item.PreferredCVSS.VectorV3, item.ID)
	}

	if *updateFixtures {
		captureFixture(t, seededDigest)
	}
}

// TestProbeReady asserts readiness answers 200 once Clair's matcher has data.
// TestMain has already waited for that, so a 503 here is the adapter's own
// readiness wiring, not a slow update.
func TestProbeReady(t *testing.T) {
	resp, body := get(t, adapterURL+"/probe/ready", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
}

// TestUnscannableArtifactIsCategorised pushes a cosign-shaped artifact: a
// manifest whose only layer is a JSON payload rather than a tarball. Nothing can
// index it, and the adapter has to say so in the category vocabulary an operator
// sees in Harbor rather than failing somewhere inside Clair.
func TestUnscannableArtifactIsCategorised(t *testing.T) {
	repository := "library/cosign-artifact"
	digest := pushCosignArtifact(t, repository)

	jobID := postScan(t, repository, digest)
	status, body := pollUntilTerminal(t, jobID)
	require.Equal(t, http.StatusInternalServerError, status,
		"an unscannable artifact must fail the scan job, got %d: %s", status, body)
	assert.Contains(t, string(body), "[unscannable_layer]",
		"the failure must carry the unscannable_layer category")
}

// waitForAdapter is a short backstop. `task compose:up` already waits on the
// container healthcheck, so this only covers a stack started by hand.
func waitForAdapter() error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		req, err := http.NewRequest(http.MethodGet, adapterURL+"/probe/healthy", nil) //nolint:noctx // bounded by the loop deadline
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no 200 from %s/probe/healthy within 2m: %v", adapterURL, err)
		}
		time.Sleep(time.Second)
	}
}

// readyTimeout is the budget for anything that waits on Clair's first update
// cycle: the matcher probe in TestMain, and the wait for CVSS enrichment inside
// the scan test.
func readyTimeout() time.Duration {
	raw := os.Getenv("COMPONENT_CLAIR_READY_TIMEOUT")
	if raw == "" {
		return defaultReadyTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		log.Fatalf("COMPONENT_CLAIR_READY_TIMEOUT %q: %v", raw, err)
	}
	return parsed
}

// waitForMatcher blocks until Clair's matcher has vulnerability data, probed the
// way the adapter's own /probe/ready does it: 202 while it has never finished an
// update, 404 once the vuln table is non-empty. This wait therefore doubles as
// that probe's proof.
//
// Note how narrow the signal is. Clair answers from SELECT EXISTS(SELECT 1 FROM
// vuln) and latches it, so it flips as soon as one alpine updater commits rows,
// which measured here is about a minute before the CVSS enricher is done. The
// CVSS assertions wait separately.
func waitForMatcher() error {
	started := time.Now()
	deadline := started.Add(readyTimeout())
	var lastStatus int
	for {
		status, err := probe(clairURL + "/matcher/api/v1/vulnerability_report/" + zeroDigest)
		switch {
		case err != nil:
			// Connection refused while Clair is still binding its listener.
		case status == http.StatusNotFound:
			log.Printf("clair matcher has vulnerability data after %s", time.Since(started).Round(time.Second))
			return nil
		case status == http.StatusUnauthorized:
			return fmt.Errorf("clair rejected the probe token after %s: the PSK in clair/config.yaml "+
				"and componentPSK in this test have diverged", time.Since(started).Round(time.Second))
		default:
			lastStatus = status
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("matcher still answering %d after %s (last error: %v)",
				lastStatus, time.Since(started).Round(time.Second), err)
		}
		time.Sleep(5 * time.Second)
	}
}

func probe(url string) (int, error) {
	status, _, err := probeBody(url)
	return status, err
}

func probeBody(url string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx // bounded by the caller's deadline
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+clairToken())
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// clairToken mints the HS256 token Clair's PSK auth expects. nbf is backdated
// because Clair allows only 15s of leeway and a container clock a few seconds
// ahead of the host's otherwise gets a 401.
func clairToken() string {
	key, err := base64.StdEncoding.DecodeString(componentPSK)
	if err != nil {
		panic("componentPSK is not base64: " + err.Error())
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": componentIssuer,
		"iat": now.Unix(),
		"nbf": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	})

	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil))
}

// resolveDigest reads the manifest digest the registry assigned to a tag. The
// registry is the authority here: computing it from the manifest bytes would
// re-implement the thing under test.
func resolveDigest(repository, tag string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, registryURL+"/v2/"+repository+"/manifests/"+tag, nil) //nolint:noctx // one call at startup
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", mediaTypeDockerManifest)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET manifest %s:%s: %d %s", repository, tag, resp.StatusCode, body)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("registry returned no Docker-Content-Digest for %s:%s", repository, tag)
	}
	return digest, nil
}

// scanUntilEnriched scans the seeded artifact until the report carries CVSS,
// and returns that report.
//
// The retry is not flake tolerance, it is the only honest signal available. The
// CVSS enricher writes its update_operation row before it inserts the rows that
// row points at, so neither the matcher probe nor the presence of an enrichment
// update operation means a report will come back enriched; the first scan after
// a cold start reliably does not. Re-indexing costs nothing after the first
// pass, because Clair keys the index report by manifest digest.
func scanUntilEnriched(t *testing.T) (harbor.ScanReport, int) {
	t.Helper()

	started := time.Now()
	deadline := started.Add(readyTimeout())
	var redirects int
	for attempt := 1; ; attempt++ {
		report, seen := pollReport(t, postScan(t, seededRepository, seededDigest))
		redirects += seen
		for _, item := range report.Vulnerabilities {
			if item.PreferredCVSS != nil && item.PreferredCVSS.ScoreV3 != nil {
				t.Logf("report carried CVSS after %s (%d scans)", time.Since(started).Round(time.Second), attempt)
				return report, redirects
			}
		}
		require.False(t, time.Now().After(deadline),
			"no finding carried preferred_cvss.score_v3 after %s and %d scans; is clair.cvss in updaters.sets?",
			time.Since(started).Round(time.Second), attempt)
		time.Sleep(5 * time.Second)
	}
}

func postScan(t *testing.T, repository, digest string) string {
	t.Helper()

	request := harbor.ScanRequest{
		// registry.url is the in-network address on purpose: the adapter fetches
		// the manifest from it and hands Clair blob URLs built on it, and Clair
		// does the fetching.
		Registry: harbor.Registry{URL: registryInNetwork},
		Artifact: harbor.Artifact{Repository: repository, Digest: digest, MimeType: mediaTypeDockerManifest},
	}
	payload, err := json.Marshal(request)
	require.NoError(t, err)

	resp, body := post(t, adapterURL+"/api/v1/scan", "application/vnd.scanner.adapter.scan.request+json; version=1.0", payload)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "body: %s", body)

	var accepted harbor.ScanResponse
	require.NoError(t, json.Unmarshal(body, &accepted))
	require.NotEmpty(t, accepted.ID)
	return accepted.ID
}

// pollReport follows the 302 ladder the way Harbor does and returns the report
// behind the eventual 200, along with how many 302s it saw. The count is
// returned rather than asserted here: on a warm Clair index a scan can finish
// between the 202 and the first poll, so it is the run as a whole that has to
// exercise the ladder, not every single poll.
func pollReport(t *testing.T, jobID string) (harbor.ScanReport, int) {
	t.Helper()

	deadline := time.Now().Add(reportPollTimeout)
	var redirects int
	for {
		resp, body := get(t, reportURL(jobID), map[string]string{"Accept": mediaTypeReport})
		switch resp.StatusCode {
		case http.StatusFound:
			redirects++
			// Harbor parses Refresh-After with ParseInt(v, 10, 8), so anything
			// above 127 is a parse error on its side.
			assert.Equal(t, "5", resp.Header.Get("Refresh-After"))
			assert.NotEmpty(t, resp.Header.Get("Location"))
		case http.StatusOK:
			assert.Equal(t, mediaTypeReport, resp.Header.Get("Content-Type"))
			var report harbor.ScanReport
			require.NoError(t, json.Unmarshal(body, &report))
			return report, redirects
		default:
			t.Fatalf("unexpected %d polling the report: %s", resp.StatusCode, body)
		}
		require.False(t, time.Now().After(deadline), "report not ready within %s", reportPollTimeout)
		time.Sleep(2 * time.Second)
	}
}

// pollUntilTerminal is pollReport's sibling for the failure path: it returns the
// first status that is not a 302.
func pollUntilTerminal(t *testing.T, jobID string) (int, []byte) {
	t.Helper()

	deadline := time.Now().Add(reportPollTimeout)
	for {
		resp, body := get(t, reportURL(jobID), map[string]string{"Accept": mediaTypeReport})
		if resp.StatusCode != http.StatusFound {
			return resp.StatusCode, body
		}
		require.False(t, time.Now().After(deadline), "scan job %s never reached a terminal state", jobID)
		time.Sleep(2 * time.Second)
	}
}

func reportURL(jobID string) string {
	return adapterURL + "/api/v1/scan/" + jobID + "/report"
}

// pushCosignArtifact writes a manifest whose single layer is a JSON payload
// carrying cosign's layer media type, and returns its digest.
func pushCosignArtifact(t *testing.T, repository string) string {
	t.Helper()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	payload := []byte(`{"critical":{"identity":{"docker-reference":"registry:5000/library/alpine"},"type":"cosign container image signature"},"optional":null}`)

	configDigest := pushBlob(t, repository, config)
	payloadDigest := pushBlob(t, repository, payload)

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaTypeDockerManifest,
		"config":        map[string]any{"mediaType": mediaTypeDockerConfig, "size": len(config), "digest": configDigest},
		"layers": []map[string]any{
			{"mediaType": mediaTypeCosignPayload, "size": len(payload), "digest": payloadDigest},
		},
	}
	body, err := json.Marshal(manifest)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, registryURL+"/v2/"+repository+"/manifests/signature", bytes.NewReader(body)) //nolint:noctx // test setup
	require.NoError(t, err)
	req.Header.Set("Content-Type", mediaTypeDockerManifest)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "putting manifest: %s", responseBody)

	digest := resp.Header.Get("Docker-Content-Digest")
	require.NotEmpty(t, digest)
	return digest
}

// pushBlob uploads one blob with the two-step start-then-complete flow every
// registry supports, and returns its digest.
func pushBlob(t *testing.T, repository string, content []byte) string {
	t.Helper()

	start, err := http.NewRequest(http.MethodPost, registryURL+"/v2/"+repository+"/blobs/uploads/", nil) //nolint:noctx // test setup
	require.NoError(t, err)
	resp, err := client.Do(start)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	complete, err := http.NewRequest(http.MethodPut, location+separator+"digest="+digest, bytes.NewReader(content)) //nolint:noctx // test setup
	require.NoError(t, err)
	complete.Header.Set("Content-Type", "application/octet-stream")
	completed, err := client.Do(complete)
	require.NoError(t, err)
	defer completed.Body.Close()
	body, _ := io.ReadAll(completed.Body)
	require.Equal(t, http.StatusCreated, completed.StatusCode, "completing blob upload: %s", body)
	return digest
}

// captureFixture rewrites the unit-test fixture from this Clair's own output, so
// pkg/clair replays real 4.x wire bytes rather than a hand-written guess.
//
// Expect a diff every time even when nothing changed: the keys of the packages
// and vulnerabilities maps are Postgres sequence values, local to whichever
// database produced the report. Read the diff for the CVE names, severities,
// fixed versions and CVSS scores, and leave the fixture alone if only the
// numbers moved.
func captureFixture(t *testing.T, digest string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, clairURL+"/matcher/api/v1/vulnerability_report/"+digest, nil) //nolint:noctx // test helper
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+clairToken())
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "fetching the report from clair: %s", body)

	path := filepath.Join("..", "..", "pkg", "clair", "testdata", "vulnerability_report_alpine310.json")
	require.NoError(t, os.WriteFile(path, body, 0o644))
	t.Logf("wrote %d bytes to %s", len(body), path)
}

func get(t *testing.T, url string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx // test helper
	require.NoError(t, err)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func post(t *testing.T, url, contentType string, payload []byte) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload)) //nolint:noctx // test helper
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}
