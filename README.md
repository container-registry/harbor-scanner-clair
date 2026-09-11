[![GitHub release][release-img]][release]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Clair

The Harbor Scanner Adapter for [Clair][clair-url] translates Harbor's scanner adapter API into
calls against a **Clair v4** (Project Quay) indexer and matcher, so Harbor can use Clair for
vulnerability reports on the images it stores.

Clair v4 inverts the adapter model of Clair 2.x. Instead of pushing layer bytes, the adapter posts
one manifest describing where the layers live and which header fetches them; Clair pulls the blobs
itself, indexes them, and computes the vulnerability report on demand. **Clair therefore needs
network access to the registry**, and the adapter never touches Clair's database.

> See [Proposal: Pluggable Image Vulnerability Scanning][image-vulnerability-scanning-proposal] for
> the Harbor side of the contract.

## TOC

* [What changed in 2.0.0](#what-changed-in-200)
* [Prerequisites](#prerequisites)
* [Configuration](#configuration)
* [Deploy with Helm](#deploy-with-helm)
* [Registering with Harbor](#registering-with-harbor)
* [Troubleshooting](#troubleshooting)
* [Contributing](#contributing)

## What changed in 2.0.0

2.0.0 is a rewrite. The adapter is maintained by [container-registry.com] and forked from
[goharbor/harbor-scanner-clair], which has had no commits since August 2020.

* **Clair v4 (4.9+) indexer and matcher API.** The v1 `/v1/layers` path and the direct PostgreSQL
  read are gone, and with them `lib/pq`, `xo/dburl` and `SCANNER_CLAIR_DATABASE_URL`. Setting that
  variable is now a startup error rather than a silent no-op.
* **JWT PSK authentication** against Clair, matching Clair's `auth.psk` block.
* **A durable job queue in PostgreSQL** with a per-job deadline and a draining shutdown, in place
  of the unbounded in-process goroutine pool. A restart no longer loses in-flight scans. Jobs live
  in one `scan_job` table that the adapter creates at startup; workers claim a row with `FOR UPDATE
  SKIP LOCKED`, so a crashed worker's job is reclaimed once its lock expires, a late write from a
  process that already lost the job cannot land, and a failure can never overwrite a finished
  report. The adapter needs no separate key-value store: Clair already requires PostgreSQL, so this
  adds nothing new to operate.
* **Reports in `application/vnd.security.vulnerability.report; version=1.1`** with
  `preferred_cvss` populated from Clair's CVSS enricher, so Harbor renders scores and vectors.
* **`kube/` is gone**, replaced by the Helm chart under [`deploy/chart`](deploy/chart).
* Scanner metadata is the constant `Clair` / `Project Quay` / `4.x`. Clair 4.9.0 exposes no release
  version over HTTP, so there is nothing to read; the vulnerability database timestamp does come
  from Clair.

Still true, and not gaps in the port:

* **Vulnerability reports only, no SBOM.** Harbor derives its registry-wide Security Hub numbers
  from the capabilities of the system-default scanner, so do not make this adapter the default if
  you also want SBOM coverage.
* **Harbor has not bundled Clair since 2.2** (`goharbor/harbor` commit `590212b48`, November 2020).
  You operate the Clair backend yourself and register this adapter with Harbor by URL.

## Prerequisites

* **Clair 4.9 or newer**, reachable from the adapter, and reachable *from Clair* to your registry.
  Clair fetches the layers.
* **A PostgreSQL database for the adapter**, with a role that owns it. The adapter creates its
  `scan_job` table there at startup. Clair's own PostgreSQL instance is the intended home: create a
  separate database on it, for example `scanner`, and point `SCANNER_STORE_POSTGRES_URL` at it. The
  adapter never touches Clair's tables.
* **Harbor 2.x**, which registers the adapter by URL.

## Configuration

Configuration is environment variables read once at startup. Anything unusable is rejected there
rather than failing on the first scan.

### General

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_LOG_LEVEL` | `info` | One of `trace`, `debug`, `info`, `warn`, `error`. `trace` means debug. |

### API server

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_API_SERVER_ADDR` | `:8080` | Binding address for the API HTTP server. |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | | Absolute path to the x509 certificate. Both this and the key, or neither. |
| `SCANNER_API_SERVER_TLS_KEY` | | Absolute path to the x509 private key. |
| `SCANNER_API_SERVER_CLIENT_CAS` | | CA bundles that verify inbound client certificates. Requires TLS. |
| `SCANNER_API_SERVER_READ_TIMEOUT` | `15s` | Maximum duration for reading the entire request. Must be positive. |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s` | Maximum duration before timing out response writes. Must be positive. |
| `SCANNER_API_SERVER_IDLE_TIMEOUT` | `60s` | How long to wait for the next request on a keep-alive connection. |
| `SCANNER_API_SERVER_METRICS_ENABLED` | `true` | Serve `/metrics`. |
| `SCANNER_API_AUTH_API_KEY` | | When set, `/api/v1/*` requires this value in `X-ScannerAdapter-API-Key`. The probes and `/metrics` are never behind it. |

### Clair

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_CLAIR_URL` | `http://clair:6060` | Clair API root. In distributed mode it must reach both the indexer and the matcher. |
| `SCANNER_CLAIR_PSK` | | Pre-shared key, base64 exactly as in Clair's `auth.psk.key`. Empty sends no `Authorization` header at all. Invalid base64 is a startup error. |
| `SCANNER_CLAIR_JWT_ISSUER` | `harbor-scanner-clair` | The `iss` claim. It must appear in Clair's `auth.psk.iss` list. |
| `SCANNER_CLAIR_INDEX_TIMEOUT` | `10m` | Bounds the synchronous index call, blob fetches included. Keep it below Harbor's registry `token_expiration` (30m by default). |
| `SCANNER_CLAIR_REQUEST_TIMEOUT` | `30s` | Bounds every other Clair call and the registry manifest fetch. |
| `SCANNER_CLAIR_REPORT_RETRY_TIMEOUT` | `5m` | Budget for the report retry loop over Clair's 202, 404 and 429 answers. |

### Store and job queue

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_STORE_BACKEND` | `postgres` | `postgres`, or `memory` for development. Memory keeps everything in one process: nothing survives a restart and a second replica shares no state. |
| `SCANNER_STORE_POSTGRES_URL` | | Connection string, `postgres://user:password@host:5432/scanner?sslmode=require`. Required when the backend is `postgres`, parsed and rejected at startup if it is not a valid DSN. Treat it as a secret. |
| `SCANNER_STORE_POSTGRES_MAX_CONNS` | `5` | Maximum connections in the pool, per replica. |
| `SCANNER_STORE_SCAN_JOB_TTL` | `1h` | How long a scan job and its report live. See the invariant below. |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` | `1` | Scans one replica runs at once. Memory is per worker; prefer more replicas. |

`SCANNER_STORE_SCAN_JOB_TTL` **must exceed the worst-case queue wait plus the worst-case scan
duration.** Harbor's report polling has no total timeout: it builds a fresh timer inside its poll
loop and throws it away on every 302, so the only thing that ends a queued job is this TTL. When
the record expires the adapter answers 404 and Harbor reports the scan as failed.

The 1.x store variables are rejected at startup rather than ignored: an upgraded deployment that
still sets them would otherwise connect nowhere and fail on the first scan.

### Outbound TLS

| Name | Default | Description |
|------|---------|-------------|
| `SCANNER_TLS_CLIENTCAS` | | CA bundles appended to the system pool used to dial Clair and the registry. Despite the name, this is outbound trust. |
| `SCANNER_TLS_INSECURE_SKIP_VERIFY` | `false` | Skip certificate verification on outbound calls. |

### Proxy

| Name | Default | Description |
|------|---------|-------------|
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | | Standard Go proxy variables, honoured on every outbound call. |

## Deploy with Helm

The chart lives in [`deploy/chart`](deploy/chart) and is published as an OCI artifact. It deploys
the adapter only: bring your own Clair 4.x and its PostgreSQL.

```
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --set clair.url=http://clair.clair.svc:6060 \
  --set clair.psk=<base64 psk>
```

[`deploy/chart/README.md`](deploy/chart/README.md) documents every value.
[`deploy/chart/example/external-clair/`](deploy/chart/example/external-clair) is a working
evaluation-grade Clair 4.x plus PostgreSQL to install alongside it.

Clair, not the adapter, fetches the layers. Whatever you deploy has to be able to reach the
registry URL Harbor sends in the scan request, which is Harbor's internal core address. Check your
NetworkPolicies and DNS in Clair's namespace before blaming the adapter.

## Registering with Harbor

In the Harbor UI go to **Administration > Interrogation Services > Scanners** and add a scanner
with the URL at which Harbor can reach the adapter. **Test Connection** calls `GET
/api/v1/metadata`, which is also the quickest check by hand:

```
curl -s http://harbor-scanner-clair:8080/api/v1/metadata | jq
```

The adapter advertises `registry-authorization-type: Bearer`. Harbor mints a pull-scoped registry
token per scan and sends it in `registry.authorization`; the adapter forwards that value verbatim
as the `Authorization` header on each layer, and Clair uses it to fetch the blob. There is no token
exchange and nothing to configure. If your registry redirects blob requests to object storage, the
redirect works: Go drops the `Authorization` header on the cross-host hop and the presigned URL
authenticates on its own.

## Troubleshooting

**Every scan sits at 202 and reports never arrive.** Clair's matcher answers `202 Accepted` until
it has vulnerability data, and the first update populates that. Watch the adapter's `/probe/ready`,
or ask Clair directly:

```
curl -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <psk jwt>" \
  http://clair:6060/matcher/api/v1/vulnerability_report/sha256:$(printf '0%.0s' {1..64})
```

`202` means not ready, `404` means ready. Note what ready means: Clair checks `SELECT EXISTS(SELECT
1 FROM vuln)` and latches the answer, so it flips as soon as **one** updater commits rows. It is
not a signal that the first update cycle finished, and never a signal that CVSS enrichment is
loaded. Right after a fresh database you can get reports with no CVSS for a minute or two.

**Scans fail with `[clair_index] ... has no index report`.** Clair returned 404 for a manifest the
adapter believed it had indexed. Usually Clair could not fetch the blobs: check Clair's own log for
`layers fetch` errors, and check that Clair can reach the registry URL from the scan request.

**Scans fail with `[clair_unavailable]` and Clair logs 429.** Clair's concurrency middleware is
rejecting requests. Lower `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` or the adapter replica count, or
raise `indexer.index_report_request_concurrency` in Clair.

**Scans fail with `[auth] clair rejected the adapter's credentials`.** Clair returned 401. Either
`SCANNER_CLAIR_PSK` does not match `auth.psk.key`, or `SCANNER_CLAIR_JWT_ISSUER` is not in Clair's
`auth.psk.iss` list. The key is base64 on both sides. Clair allows 15s of clock leeway.

**The adapter exits at startup on `applying the scan_job schema`.** The role in
`SCANNER_STORE_POSTGRES_URL` cannot create the table. The adapter runs `CREATE TABLE IF NOT EXISTS
scan_job` and two `CREATE INDEX IF NOT EXISTS` statements on every start, so the role has to own
the database or hold `CREATE` on its schema. Either grant it, or create the table by hand with the
DDL in `pkg/persistence/postgres/store.go` and grant the role `SELECT, INSERT, UPDATE, DELETE` on
it.

**Scans fail with `[unscannable_layer]`.** The artifact is not an image Clair can index: a cosign
signature, an SBOM attestation, or a Windows image with foreign layers. Harbor scans these because
they are artifacts in the repository; the failure is correct.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the test tiers and the commit
conventions releases depend on.

[release-img]: https://img.shields.io/github/release/container-registry/harbor-scanner-clair.svg
[release]: https://github.com/container-registry/harbor-scanner-clair/releases
[report-card-img]: https://goreportcard.com/badge/github.com/container-registry/harbor-scanner-clair
[report-card]: https://goreportcard.com/report/github.com/container-registry/harbor-scanner-clair
[license-img]: https://img.shields.io/github/license/container-registry/harbor-scanner-clair.svg
[license]: https://github.com/container-registry/harbor-scanner-clair/blob/main/LICENSE

[container-registry.com]: https://container-registry.com
[goharbor/harbor-scanner-clair]: https://github.com/goharbor/harbor-scanner-clair

[clair-url]: https://github.com/quay/clair
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
