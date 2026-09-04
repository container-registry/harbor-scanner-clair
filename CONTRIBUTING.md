# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Build](#build)
* [Run Tests](#run-tests)
* [Check for Vulnerabilities](#check-for-vulnerabilities)
* [Test Against a Local Harbor](#test-against-a-local-harbor)
* [Commit Conventions](#commit-conventions)

## Set up Local Development Environment

1. Install Go.

   The required Go version is declared in [`go.mod`](go.mod).
2. Install [Task](https://taskfile.dev) and Docker.
3. Get the source code.
   ```
   git clone https://github.com/container-registry/harbor-scanner-clair.git
   cd harbor-scanner-clair
   ```
4. Install pinned development tools and git hooks.
   ```
   task setup
   ```

Tool and base-image version pins live in [`versions.env`](versions.env). No key in that file
may start with `SCANNER_`: the Taskfile loads it as dotenv, so every key is exported into
every task, and the adapter itself reads `SCANNER_*` at runtime.
Run `task --list` to see all available tasks and `task info` for the build configuration.

## Build

Build the binary into `bin/linux-<arch>/scanner-clair`. The default target is Linux on your
native architecture; pass `PLATFORMS=linux/amd64,linux/arm64` to cross-compile:

```
task build
```

Build a local container image `harbor-scanner-clair:<version>`:

```
task image:local
```

## Run Tests

Unit testing alone doesn't provide guarantees about the behaviour of the adapter. To verify that each Go module
correctly interacts with its collaborators, more coarse grained testing is required as described in
[Testing Strategies in a Microservice Architecture][fowler-testing-strategies].

```
task test              # unit tests with race detection and coverage
task test:integration  # integration tests (requires Docker)
task lint              # golangci-lint in Docker; task lint:local uses the pinned binary
```

## Check for Vulnerabilities

Scan the module dependency graph with the pinned [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck):

```
task vuln-check
```

CI runs the same scan through `task vuln-report`, which stores the raw JSON in
`vulnerability-check/` and renders it into markdown. Run it locally to see exactly what CI
reports:

```
task vuln-report                       # writes vulnerability-check/report.md and comment.md
cat vulnerability-check/report.md      # every finding
cat vulnerability-check/comment.md     # only findings with a published fix
```

`report.md` goes to the workflow job summary and `comment.md` becomes a sticky pull request
comment that is updated on every re-run and removed once nothing fixable is left. Findings do
not fail the job; only a govulncheck run that could not produce a usable report does, which
`task vuln-report:check` verifies.

The renderer lives in [`tools/govulncheck-report`](tools/govulncheck-report) and can also be
pointed at a report you produced yourself:

```
govulncheck -format json ./... > govulncheck.json
go run ./tools/govulncheck-report -json govulncheck.json -mode fixable
```

## Test Against a Local Harbor

Harbor has not shipped Clair since 2.2, so there is no adapter service in a Harbor deployment
to repoint at a local build. Harbor talks to this adapter over the network instead, and you
register it by URL:

1. Build the image and start it next to a Clair 2.x server and a Redis, on an address the
   Harbor core container can reach. `task info` prints the version the image is tagged
   with:
   ```
   task image:local
   docker run --rm -p 8080:8080 \
     -e SCANNER_CLAIR_URL=http://clair:6060 \
     -e SCANNER_STORE_REDIS_URL=redis://redis:6379 \
     harbor-scanner-clair:<version>
   ```
   Both URLs are resolved from inside the container. `task run` does the same without a
   container, on `:8080` with debug logging.
2. In the Harbor UI, go to Administration > Interrogation Services > Scanners and add a
   scanner with that URL. **Test Connection** calls `GET /api/v1/metadata`, which is also the
   quickest way to check the adapter by hand:
   ```
   curl -s http://localhost:8080/api/v1/metadata | jq
   ```

## Commit Conventions

Releases are automated with [release-please](https://github.com/googleapis/release-please);
see [docs/RELEASES.md](docs/RELEASES.md). Two rules follow from that:

* Commit messages (and PR titles, which become the squash commit) follow
  [Conventional Commits](https://www.conventionalcommits.org): `feat:` triggers a minor
  release, `fix:` a patch release; `chore:`/`ci:`/`build:`/`test:` do not trigger releases.
* Every commit must carry a DCO sign-off (`git commit -s`).

Both are enforced locally by [lefthook](lefthook.yml) hooks (installed via `task setup`)
and in CI.

[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
