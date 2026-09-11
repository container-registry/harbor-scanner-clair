# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Harbor Scanner Adapter for Clair: a Go microservice that translates Harbor's scanner adapter
API into calls against a **Clair v4** (Project Quay) indexer and matcher. It accepts scan
requests over HTTP, runs them through a durable job queue held in a PostgreSQL table, and
serves the resulting vulnerability reports back to Harbor. Harbor removed its bundled Clair in 2.2
(`goharbor/harbor` commit `590212b48`), so the Clair backend is operated separately and this
adapter is registered with Harbor by URL.

Clair v4 inverts the Clair 2.x adapter model: the adapter posts one manifest describing where
the layers live and which header fetches them, and Clair pulls the blobs itself. The adapter
never touches Clair's database, and Clair needs network access to the registry.

Module: `github.com/container-registry/harbor-scanner-clair`, go directive `1.27.1`.

## Build & Test Commands

```bash
task build              # Build the Linux binary for the native arch into bin/linux-<arch>/
task test               # Unit and contract tests with race detection and coverage
task test:postgres      # Store and queue tests against a throwaway Postgres container
task compose:up         # Bring up the component stack (Clair 4.x, Postgres, registry, adapter)
task test:component     # Component tier against that stack (build tag: component)
task compose:down       # Tear it down, volumes included
task lint               # golangci-lint in Docker; task lint:local uses the pinned binary
task lint:yaml          # yamllint
task vuln-check         # govulncheck over the module graph
task vuln-report        # The same scan rendered to markdown, which is what CI posts
task image:local        # Build a local image harbor-scanner-clair:<version>
task run                # Run locally on :8080 with debug logging and the memory store
task helm:ci            # Every chart gate; see taskfile/helm.yml for the individual ones
task info               # Version, tool pins and build configuration
```

Tool and base-image pins live in `versions.env`, loaded by the Taskfile via dotenv. No key in
that file may start with `SCANNER_`: dotenv exports every key into the environment of every
task, and the adapter reads `SCANNER_*` at runtime (`pkg/etc/config.go`), so such a pin would
poison `task test` and `task run`. `CLAIR_VERSION` and `CLAIR_POSTGRES_VERSION` live there
for the component compose and the chart examples; the adapter must never read either, which
is also why the scanner version it advertises is a constant and not an environment read.

Releases are automated with release-please. There are two independent release lines, the
adapter (`vX.Y.Z`) and the chart (`chart-vX.Y.Z`), each with its own config, manifest and
changelog. Never push tags manually (see docs/RELEASES.md).

Run a single test:
```bash
go test -v -run TestFunctionName ./pkg/scan/...
```

Run a single component test (the stack has to be up):
```bash
go test -v -tags=component -run TestScanSeededArtifact ./test/component/...
```

The Postgres store and queue tests need a real database and skip themselves when
`SCANNER_TEST_POSTGRES_URL` is unset, which is what keeps `task test` runnable with no services.
`task test:postgres` starts a throwaway container, exports that variable and runs them; CI does the
same with a Postgres service container. A green `task test` therefore says nothing about the
Postgres paths.

## Architecture

**Request flow:**
1. `POST /api/v1/scan`: the v1 handler validates the request synchronously and answers 422 for
   anything it can never satisfy, the enqueuer inserts a `Queued` row into `scan_job`, and the
   handler answers 202 with the job id.
2. A worker claims the oldest claimable row in one `UPDATE ... FOR UPDATE SKIP LOCKED`, which
   also sets `locked_until` and bumps `attempts`, and runs the job under a deadline derived from
   the Clair timeouts. The deadline is shorter than the lock, so a live worker never outlives
   its claim and a crashed one is reclaimed when `locked_until` passes.
3. The controller fetches the artifact manifest from the registry with the authorization
   Harbor minted, rejects anything Clair cannot index, and builds a Clair manifest: the
   artifact digest as the hash, one layer per manifest layer, each with the blob URL and the
   `Authorization` header.
4. `POST /indexer/api/v1/index_report` blocks until Clair has fetched and indexed every layer,
   then `GET /matcher/api/v1/vulnerability_report/{digest}` retries over Clair's 202, 404 and
   429 answers until the report arrives.
5. The transformer maps that report onto Harbor's model and the store records it as
   `Finished`.
6. `GET /api/v1/scan/{scan_request_id}/report`: 302 with `Location` and `Refresh-After` while
   the job is queued or pending, 500 with the recorded categorised error if it failed,
   otherwise the stored report bytes.

**Key packages:**
- `cmd/harbor-scanner-clair/` -- entry point; `run()` wires config, the Clair client, the store, the queue pair, metrics, the readiness closure, the API handler and the server, then traps SIGINT/SIGTERM and drains
- `pkg/etc/` -- configuration from `SCANNER_*` environment variables, parsed with `caarlos0/env/v6` and validated at startup; the derived job deadline and lock TTL; the startup checker
- `pkg/harbor/` -- Harbor adapter wire types: `ScanRequest`, `ScanReport`, the seven-value `Severity`, and the constant scanner block
- `pkg/http/api/` -- HTTP server, MIME-type parsing and JSON writers
- `pkg/http/api/v1/` -- route table, request validation, the report status ladder, `/metadata`, the probes
- `pkg/clair/` -- the Clair v4 client: wire structs, status handling and retries, the CVSS enrichment decoder, and the hand-rolled PSK signer
- `pkg/registry/` -- fetches the artifact manifest, forwarding Harbor's `Authorization` value verbatim
- `pkg/scan/` -- `controller.go` (one job end to end), `transformer.go` (Clair to Harbor), `errors.go` (the category vocabulary)
- `pkg/persistence/` -- the `Store` interface, `codec.go` (gzip plus a size cap for the report column), and the `postgres/` (pgx v5 `pgxpool`, the `scan_job` DDL and every statement) and `memory/` implementations
- `pkg/queue/` -- `enqueuer.go`, `postgres.go` (the claim loop, the expiry sweep and the depth gauge) and the in-process queue the memory backend uses
- `pkg/job/` -- the `Status` enum and the `ScanJob` record
- `pkg/metrics/` -- the `harbor_scanner_clair_*` collectors
- `test/contract/` -- Harbor's own `ScannerAdapterMetadata.Validate()`, vendored, run against the served document
- `test/component/` -- the compose stack and the end-to-end tier

**API endpoints:**
- `POST /api/v1/scan` -- submit a scan request
- `GET /api/v1/scan/{scan_request_id}/report` -- retrieve the scan report
- `GET /api/v1/metadata` -- adapter metadata and capabilities
- `GET /probe/healthy`, `GET /probe/ready` -- health probes
- `GET /metrics` -- Prometheus metrics

## Key Design Decisions

- **Bearer passthrough.** Harbor mints a pull-scoped registry token per scan and sends it in
  `registry.authorization`. The adapter GETs the manifest with it and forwards it unchanged as
  each layer's `Authorization` header, and advertises
  `registry-authorization-type: Bearer` accordingly. No token exchange, no `WWW-Authenticate`
  dance, no go-containerregistry. Two consequences: **Clair** needs the route to the registry,
  not the adapter alone; and the token has to still be valid when Clair fetches, which it is,
  because indexing happens synchronously inside the adapter's own POST. A registry that
  redirects blobs to object storage works because Go drops the header on the cross-host hop
  and the presigned URL authenticates on its own.
- **No index-report deletion.** Clair's storage is content-addressed and shared between
  manifests, and `CheckManifest` makes re-indexing the same digest cheap. Deleting after each
  scan destroys that. Quay deletes only when a manifest is deleted, never per scan.
- **A Postgres table instead of a key-value store.** Clair already requires PostgreSQL, so the
  adapter's `scan_job` table adds no service to operate; by default it lives in its own database
  on the same instance and the adapter creates it with idempotent DDL at startup. One statement
  claims a job (`UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1)`), replacing a
  push, a blocking move, a processing list, a `SetNX` lock and an orphan-requeue pass, and a
  killed worker's row is reclaimed once `locked_until` lapses. Terminal writes are conditional on
  the status they expect to find (`Finish` only from `Pending` and only before `expires_at`, a
  failure only from `Queued` or `Pending`), which closes the crash and overwrite races the
  key-value design had: a late failure cannot replace a stored report, and an expired record is
  reported gone rather than resurrected.
- **The TTL invariant.** Harbor's report polling has no total timeout: it builds a fresh
  `time.After` inside its poll loop and throws it away on every 302, so the 30 minutes bound
  the gap between responses, not the total wait. The effective deadline on a queued job is
  `SCANNER_STORE_SCAN_JOB_TTL`, so that TTL must exceed the worst-case queue wait plus
  the worst-case scan duration.
- **`Refresh-After` must be <= 127.** Harbor parses it with `strconv.ParseInt(v, 10, 8)`.
- **Severity mapping is the identity function.** claircore's `normalized_severity` enum is
  exactly Harbor's set. The CVSS base score is a fallback used only when the normalized value
  is `Unknown`, which for Alpine content is most of the time.
- **Scanner metadata is a constant**, `Clair` / `Project Quay` / `4.x`. Clair 4.9.0 sets no
  version header and its OpenAPI `info.version` is the API version, so there is nothing to
  read. The vulnerability database timestamp does come from Clair, via the matcher's
  `update_operation` endpoint, and is simply omitted when that call fails.
- **Re-index on `index_state`, not on database updates.** The matcher recomputes the report on
  every query, so a moved vulnerability database needs no new index report; a changed indexer
  configuration does.
- **Vulnerability reports only, no SBOM.** Harbor's Security Hub derives its registry-wide
  numbers from the capabilities of the system-default scanner, so making this adapter the
  default zeroes them for anyone who also expects SBOM coverage.
- **Divergences from the house style, on purpose.** No `golang.org/x/xerrors`
  (`fmt.Errorf("%w")` since Go 1.13), no `samber/lo` (the transformer's `Map`/`MaxBy` are six
  lines of `slices`), and no claircore or clair import (six wire structs against a dependency
  tree of grpc, a dozen OpenTelemetry modules and rabbitmq). The scan job key is a plain
  string id rather than the composite key `dependencytrack-harbor-adapter` uses.
- All configuration is environment variables prefixed `SCANNER_`. No config files.
- Version, commit and build date are injected via ldflags by `task build`.
