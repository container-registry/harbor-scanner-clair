# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Harbor Scanner Adapter for Clair: a Go microservice that translates Harbor's scanner adapter
API into calls against a CoreOS Clair 2.x server. It accepts scan requests over HTTP, runs
them asynchronously on an in-process goroutine pool, and stores the resulting vulnerability
reports in Redis. Harbor removed its bundled Clair in 2.2 (`goharbor/harbor` commit
`590212b48`), so the Clair backend has to be operated separately and this adapter registered
with Harbor by URL.

Module: `github.com/container-registry/harbor-scanner-clair`, go directive `1.27.1`.

## Build & Test Commands

```bash
task build              # Build the Linux binary for the native arch into bin/linux-<arch>/
task test               # Unit tests with race detection and coverage
task test:integration   # Integration tests (build tag: integration, testcontainers + Docker)
task lint               # golangci-lint in Docker; task lint:local uses the pinned binary
task vuln-check         # govulncheck over the module graph
task vuln-report        # The same scan rendered to markdown, which is what CI posts
task image:local        # Build a local image harbor-scanner-clair:<version>
task run                # Run locally on :8080 with debug logging
task info               # Version, tool pins and build configuration
```

There is no component test tier: `task test` and `task test:integration` are the whole suite.
There are no `helm:*` tasks yet either. The Helm chart and its separate `chart-vX.Y.Z`
release line are added in a later change; `taskfile/helm.yml` is already included with
`optional: true` so `task --list` works until it lands.

Tool and base-image pins live in `versions.env`, loaded by the Taskfile via dotenv. No key in
that file may start with `SCANNER_`: dotenv exports every key into the environment of every
task, and the adapter reads `SCANNER_*` at runtime (`pkg/etc/config.go`), so such a pin would
poison `task test` and `task run`.

Releases are automated with release-please. There is one release line today, the adapter
(`vX.Y.Z`), with its own config, manifest and changelog; the chart adds a second, independent
line. Never push `v*` tags manually (see docs/RELEASES.md).

Run a single test:
```bash
go test -v -run TestFunctionName ./pkg/scanner/...
```

Run a single integration test:
```bash
go test -v -tags=integration -run TestName ./test/integration/...
```

## Architecture

**Request flow:**
1. `POST /api/v1/scan`: the v1 handler validates the request, the enqueuer writes a `Pending`
   job to Redis and submits a worker to the `pkg/work` pool, and the handler answers 202 with
   the job ID.
2. The worker marks the job `Running`, fetches the image manifest from the registry
   (`pkg/registry`, schema2 only), turns its layers into Clair layers
   (`pkg/scanner/transformer.go`), posts each one to Clair's `POST /v1/layers`, reads the top
   layer back with `GET /v1/layers/{name}?features&vulnerabilities`, transforms that into a
   Harbor report, and stores the report and the `Finished` status in Redis.
3. `GET /api/v1/scan/{scan_request_id}/report`: 302 with a `Location` header while the job is
   `Pending` or `Running`, 500 with the recorded error if it `Failed`, otherwise the report.

`pkg/work` is a 36-line channel-based pool that starts one unbounded goroutine per task. It
is not a durable queue: no concurrency cap, no retries, no backpressure beyond the unbuffered
channel, and `Shutdown()` does not wait for in-flight work despite its doc comment. A restart
loses every running scan and leaves its Redis record `Running` until the TTL expires. Redis
is a result store only.

**Key packages:**
- `cmd/harbor-scanner-clair/` -- entry point; `run()` wires config, Redis pool, store, work pool, registry client factory, Clair client, adapter, enqueuer, API handler and server, then traps SIGINT/SIGTERM
- `pkg/etc/` -- configuration from environment variables prefixed `SCANNER_`, parsed with `caarlos0/env/v6`; also `GetLogLevel()` and `GetScannerMetadata()`
- `pkg/harbor/` -- Harbor adapter wire types (ScanRequest, ScanReport, Severity with custom JSON marshaling)
- `pkg/clair/` -- HTTP client for the Clair v1 REST API, plus the direct PostgreSQL query for the vulnerability database timestamp
- `pkg/registry/` -- fetches the image manifest from Harbor's registry, passing the `Authorization` value out of the scan request straight through; `schema2` manifests only
- `pkg/scanner/` -- `adapter.go` (orchestration), `transformer.go` (Clair to Harbor mapping), `enqueuer.go`, `worker.go`
- `pkg/persistence/` -- the `Store` interface: Create, Get, UpdateStatus, UpdateReport
- `pkg/persistence/redis/` -- redigo implementation; keys `<namespace>:scan-job:<id>`, `SET` with `NX`/`XX` and `EX <ttl>`
- `pkg/redisx/` -- pool constructor for `redis://` and `redis+sentinel://` URLs
- `pkg/job/` -- `Status` enum (Pending, Running, Finished, Failed) and the `ScanJob` struct
- `pkg/work/` -- the goroutine pool described above
- `pkg/http/api/` -- HTTP server, MIME-type helpers, JSON writers
- `pkg/http/api/v1/` -- route table and request handlers
- `pkg/mock/` -- hand-written testify mocks and an `ApplyExpectations` dispatcher

**API endpoints:**
- `POST /api/v1/scan` -- submit a scan request
- `GET /api/v1/scan/{scan_request_id}/report` -- retrieve the scan report
- `GET /api/v1/metadata` -- adapter metadata and capabilities
- `GET /probe/healthy`, `GET /probe/ready` -- health probes
- `GET /metrics` -- Prometheus metrics

## Key Design Decisions

- The backend is the **Clair v1 API** (CoreOS Clair 2.x): `POST /v1/layers` and
  `GET /v1/layers/{name}`. There is no support for the Clair v4 indexer and matcher split.
  Upstream issue #24 has asked for 4.x since 2021.
- The adapter implements **Harbor adapter API v1.0 only**. Every MIME type in
  `pkg/http/api/base_handler.go` carries `version=1.0`: no SBOM report type, no capability
  negotiation. Harbor's Security Hub derives its registry-wide numbers from the capabilities
  of the system-default scanner, so making this adapter the default would zero them.
- `GetScannerMetadata()` in `pkg/etc/config.go` **hardcodes** Name `Clair`, Vendor `CoreOS`,
  Version `2.x`. Nothing asks the backend what it actually is.
- All configuration is environment variables prefixed `SCANNER_`. No config files.
- `SCANNER_CLAIR_DATABASE_URL` makes the adapter connect to Clair's PostgreSQL directly and
  run `SELECT value from keyvalue where key = 'updater/last'` for the vulnerability database
  timestamp in the metadata response. That one query is the only reason `lib/pq` and
  `xo/dburl` are in `go.mod`. Unset, the timestamp is simply omitted.
- Redis is the result store, not a queue: one JSON blob per job under
  `<namespace>:scan-job:<id>`, created with `NX` and updated with `XX`, expiring after
  `SCANNER_STORE_REDIS_SCAN_JOB_TTL`. `pkg/redisx` also accepts `redis+sentinel://` URLs.
- The Redis client is pinned at `github.com/gomodule/redigo v2.0.0+incompatible`. That is a
  pre-modules tag which sorts *above* the maintained v1.9.x line, so no updater will ever
  propose a bump and `go get -u` will not move it. Moving to v1.9.x is a deliberate migration,
  not a dependency bump.
- `/metrics` is served by `promhttp.Handler()` unconditionally, with the default Go and
  process collectors only. There are no scanner-specific metrics and no toggle.
- `GetHealthy` and `GetReady` both return 200 unconditionally. Readiness never checks Redis
  or Clair, so a ready pod proves nothing about the backend.
- Version, commit and build date are injected via ldflags by `task build`.

## Known rough edges

Real defects in code this port deliberately does not touch. Do not fix them as a side effect
of build or release work; each needs its own change and a test.

- `pkg/clair/client.go:120` -- `log.Fatal(err)` inside the database row-scan loop kills the
  whole process on a scan error.
- `pkg/registry/client.go:44` -- the registry client is built under a package-level
  `sync.Once`, so the first caller's TLS configuration wins for the lifetime of the process
  and the factory cannot be tested.
- `pkg/scanner/adapter.go:52` -- `layers[len(layers)-1]` is indexed with no length check. A
  zero-layer image panics the worker (upstream issue #14).
- `pkg/persistence/redis/store.go:102` -- `UpdateStatus` dereferences the result of `Get`,
  which returns `nil, nil` for a missing key, so an expired job ID panics the worker
  goroutine.
- `pkg/http/api/server.go:49` -- the hardened `tls.Config` (MinVersion, cipher suites, curve
  preferences) is assigned on the plaintext branch, after the TLS branch has already
  returned. It never applies to a TLS listener.

`pkg/clair`, `pkg/registry`, `pkg/work` and `pkg/persistence/redis` have no unit tests at all;
six test files are a bare package clause.
