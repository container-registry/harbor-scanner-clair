# Release Process

Releases are automated with [release-please](https://github.com/googleapis/release-please). Do not create `v*` or `chart-v*` tags, or GitHub Releases, manually.

There are **two independent release lines**, each with its own release-please
instance, config, manifest, changelog and tag namespace:

| Line | Covers | Tag | Config / manifest | Changelog |
|------|--------|-----|-------------------|-----------|
| Adapter | everything except `deploy/`, `.github/`, `docs/`, `taskfile/`, `.release-please/` | `vX.Y.Z` | `.release-please/config-adapter.json` / `.release-please/manifest-adapter.json` | `CHANGELOG.md` |
| Helm chart | `deploy/chart/` | `chart-vX.Y.Z` | `.release-please/config-chart.json` / `.release-please/manifest-chart.json` | `deploy/chart/CHANGELOG.md` |

They are separate so a chart fix does not force an adapter release that
republishes an identical image, and an adapter release does not republish the
chart by itself. The two are linked in one direction only: the adapter line owns
`appVersion` in `deploy/chart/Chart.yaml` (via the `x-release-please-version`
marker), the chart line owns `version`. Because the adapter release commit
touches `Chart.yaml`, and `chore:` is visible in the chart changelog, every
adapter release also opens or refreshes the chart release PR with a
`release adapter X.Y.Z` entry; merging that PR publishes a chart whose
`appVersion` is the new adapter. Both lines are driven by the same
`Release Please` workflow on every push to `main`.

Release state is defined by:

- Conventional squash commit titles on `main`
- The config and manifest files above (each manifest holds its line's last published version)
- The changelogs above

The adapter manifest starts at `1.1.1`, continuing the version line the upstream project
published on Docker Hub for the same adapter. The matching tag does not exist in
this fork; that is harmless because `bootstrap-sha` supplies the history floor.
It is inclusive, so commits at or before it are ignored: it is pinned to the last
commit of the fork's infrastructure port, which keeps the 44 upstream commits
below it, several of them conventional, out of `CHANGELOG.md`. Upstream's own
releases are linked from the top of that file instead.

The chart manifest starts at `0.0.0`, so the chart's first release is `0.1.0`
with no `release-as` override. Pre-1.0 is deliberate: this chart has no
predecessor and fronts a backend Harbor dropped in 2.2, so `1.0.0` would
advertise a stability promise it has not earned. `bump-minor-pre-major` in the
chart config then keeps a breaking chart change at a minor bump instead of
jumping to `1.0.0`. Its `bootstrap-sha` is pinned the same way, to the commit
before the chart landed.

## How It Works

1. PRs are squash-merged to `main` with conventional commit titles. The PR title becomes the commit release-please parses, so the repository must allow **squash merging only** (disable merge commits and rebase merging).
2. On every push to `main`, the `Release Please` workflow opens or updates a release PR **per line**, for whichever line has releasable commits:
   - `chore: release adapter X.Y.Z` bumps `.release-please/manifest-adapter.json`, updates `CHANGELOG.md`, and stamps `appVersion` into `deploy/chart/Chart.yaml`.
   - `chore: release chart X.Y.Z` bumps `.release-please/manifest-chart.json`, updates the chart's `CHANGELOG.md`, and stamps `version` into `Chart.yaml` and the cosign example in the chart `README.md`.
3. Squash-merging a release PR creates its tag (`vX.Y.Z` or `chart-vX.Y.Z`) and GitHub Release.
4. An **adapter** release then automatically:
   - builds and pushes the multi-arch (`linux/amd64`, `linux/arm64`) image `8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z`
   - signs the image with cosign (keyless) and attaches an SPDX SBOM attestation
   - uploads the adapter binaries as release assets
   - appends image references and cosign verification commands to the release notes
   - opens or refreshes the chart release PR (`chore: release chart X.Y.Z`), so a chart with the new `appVersion` ships as soon as that PR is merged
5. A **chart** release automatically:
   - appends the per-release `artifacthub.io/images` annotation to `Chart.yaml` (not committed - the tag is only known at release time)
   - packages the chart at the tag's version and pushes it to `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair`
   - signs the chart with cosign (keyless)
   - pushes `artifacthub-repo.yml` as a separate OCI artifact under the `artifacthub.io` tag, which is what gives Artifact Hub the ownership metadata
   - appends install and verification instructions to the chart release notes

   The chart release does **not** wait on an image build: the chart references
   the adapter by `appVersion`, which a prior adapter release must already have
   published.

Every push to `main` additionally publishes `8gears.container-registry.com/8gcr/harbor-scanner-clair:latest` via the `Main Image` workflow.

## Version Rules

A release PR opens as soon as a line has at least one commit of a type that is
shown in its changelog. Hidden types never open a release on their own. The
bump is decided by the highest-ranking commit: breaking > `feat:` > everything
else.

| Commit type | Bump | Notes section |
|-------------|------|---------------|
| `feat!:` or `BREAKING CHANGE:` | Adapter: Major. Chart: Minor while pre-1.0, via `bump-minor-pre-major` | Breaking changes |
| `feat:` | Minor | Features |
| `fix:` | Patch | Bug Fixes |
| `perf:`, `upstream:`, `revert:`, `refactor:`, `docs:` | Patch | Performance Improvements, Upstream, Reverts, Code Refactoring, Documentation |
| `chore:` | Adapter: hidden, no release. Chart: Patch | Chart only: Miscellaneous. This is what carries an adapter release (`chore: release adapter X.Y.Z` stamps `appVersion`) into a chart release |
| `ci:`, `build:`, `test:` | Hidden, no release | - |

Use `upstream:` for changes synced from `goharbor/harbor-scanner-clair`. The
cherry-pick workflow writes that type into the PR title for you.

The same rules apply to both lines, except that `chore:` is shown only in the
chart changelog. Which line a commit lands on is decided by its paths: the
adapter line ignores `.github/`, `docs/`, `deploy/`, `taskfile/` and
`.release-please/`; the chart line only sees `deploy/chart/`. A commit touching
both opens both release PRs. Use `ci:` for workflow-only changes.

Scope chart commits `feat(chart):` / `fix(chart):` and keep them inside the
paths the adapter ignores. One file outside, even `README.md`, puts the commit
in the adapter changelog and bumps the adapter version. The `Chart Scope Paths`
check fails such a PR; split it rather than retype it. When `exclude-paths` in
`.release-please/config-adapter.json` changes, update that check's patterns too.

## Tracking the base image

The adapter image is built `FROM` Alpine and bundles the `lprobe` healthcheck
binary. Both pins live in `versions.env`, which is invisible to dependabot, so
each carries a `# renovate:` annotation read by the regex manager in
`renovate.json`. Both use the `docker` datasource, so a bump PR only appears once
the tag actually exists.

`renovate.json` maps both to `fix:`, so squash-merging the Renovate PR makes
release-please cut a matching adapter patch release. An Alpine minor bump changes
what ships but adds no adapter feature, which is why it is not `feat:`.
`versions.env` sits on the adapter release line, so a pin bump releases the
adapter artifacts.

Renovate is limited to `versions.env` (`enabledManagers: custom.regex`);
dependabot keeps gomod and github-actions. The tooling pins are
bumped as `ci(deps):`, which the adapter line hides. `TYPOS_VERSION` is
deliberately unmanaged: its hand-computed `TYPOS_SHA256_LINUX_X86_64` companion
has to be recomputed in the same commit, and a stale checksum failing the
hygiene job is the reminder.

## Tracking upstream goharbor

`goharbor/harbor-scanner-clair` has not moved since 2020-08-20, and Harbor has
not bundled Clair since 2.2. That is why the `Upstream Cherry-Pick` workflow is
`workflow_dispatch`-only with no cron: a scheduled run would fetch the whole
history twice a day to find nothing. Upstream is not archived, so the mechanism
stays for the day something does land there.

Run it by hand (`gh workflow run upstream-cherry-pick.yml -f dry_run=true` first).
The PRs it opens are titled `upstream: <subject>`, which is a visible type, so
merging one cuts a patch release.

## Behaviour that looks like a bug

Each of these cost someone a debugging session on the sibling repository.

- **An open release PR goes stale after a config or changelog change.** release-please rewrites an open release PR only when its body would change, so an edit that leaves the body identical is silently dropped. `always-update: true` in `.release-please/config-adapter.json` forces the rewrite. Do not remove it.
- **`release-as` is permanent, not one-shot.** Setting it does not pin one release, it pins every release after it to the same version. There is no `release-as` here and none may be added; use a conventional commit type to get the bump you want.
- **`exclude-paths` is evaluated per file.** A commit is dropped from the adapter line only when **every** file it touches is excluded. A chart-scoped commit that also edits one file at the repo root, even `README.md`, pulls the whole commit back into the adapter changelog and bumps the adapter version.
- **A hidden commit type cannot carry a release into a second release-please package.** The `chore: release adapter X.Y.Z` commit of one line is just a `chore:` to the other. `chore:` is hidden here, which is correct for the adapter, but the chart config must make it **visible** or the chart line sees an empty changelog and never opens a PR after an adapter release restamps `appVersion`. That asymmetry between the two configs is load-bearing, not an oversight.
- **The release PR has no checks.** Refs pushed with `GITHUB_TOKEN` raise no workflow runs. Never mark any check required on this repository, or the release PR can never be merged.
- **Editing the config on a branch changes nothing.** release-please reads its config and manifest from the **remote default branch**, not from the PR's working tree. A config change is only observable after it is merged to `main`.

## Release Artifacts

| Artifact | Location |
|----------|----------|
| Container image | `8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z` (and `:latest` from `main`) |
| Helm chart | `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:X.Y.Z`, cosign-signed |
| Artifact Hub repo metadata | `oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:artifacthub.io` |
| Adapter binaries | `scanner-clair_linux-{amd64,arm64}.tar.gz` release assets |
| Checksums | `checksums.txt` release asset (SHA256 of all tarballs) |
| Changelog | `CHANGELOG.md`, `deploy/chart/CHANGELOG.md` and the GitHub Releases |

Install the chart:

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --version X.Y.Z
```

Verify an image signature:

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-clair/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z
```

Verify a chart signature:

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-clair/.github/workflows/publish-chart.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:X.Y.Z
```

Verify the SBOM attestation:

```sh
cosign verify-attestation \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-clair/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson \
  8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z
```

Verify the published architectures:

```sh
task image:verify IMAGE_TAG=vX.Y.Z
```

The publish workflow runs the same check on the pushed digest, so a build that
loses an architecture fails the release instead of shipping. The task asserts
the reference is an OCI image index whose platforms are exactly
`IMAGE_PLATFORMS` (`linux/amd64,linux/arm64`); `IMAGE_REF=...` verifies an
arbitrary reference, `PLATFORMS=...` a different expectation.

## Required Configuration

| Name | Type | Required | Purpose |
|------|------|----------|---------|
| `REGISTRY_ADDRESS` | Variable | No | Registry host, defaults to `8gears.container-registry.com` |
| `REGISTRY_PROJECT` | Variable | No | Registry project, defaults to `8gcr` |
| `REGISTRY_ALLOWLIST` | Variable | No | Comma-separated hosts `publish-chart.yml` may push to, defaults to `8gears.container-registry.com` |

`REGISTRY_ALLOWLIST` is worth setting explicitly. `publish-chart.yml` takes
`registry_address` as a free-form `workflow_dispatch` input and mints an OIDC
token with that host as its audience, so the allowlist is what stops a signed
identity token reaching a registry we do not control.

Artifact Hub listing (one-off): add the repository at
[artifacthub.io](https://artifacthub.io) as kind *Helm*, URL
`oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair`, then put
the ID it assigns into `repositoryID` in `deploy/chart/artifacthub-repo.yml` to
enable the verified-publisher badge.

There is no registry password anywhere: publish jobs authenticate keyless through
Harbor's Federated Identity Provider. The job mints a GitHub OIDC token
(`id-token: write`, audience `https://<registry>`), logs in with `-u jwt` and the
token as password, and Harbor maps it to the federated robot
`robot_gh-scanner-clair-push` via a claim rule that only matches this repository's
tokens (`repository == container-registry/harbor-scanner-clair`). That robot needs
push on the chart path (`8gcr/charts/harbor-scanner-clair`) as well as the image
path. The robot has no secret; there is nothing to rotate or leak. See
[harbor-workload-identity-federation](https://github.com/container-registry/harbor-workload-identity-federation).

Repository settings:

- Enable only **Allow squash merging**.
- Set the squash commit title to **Default to pull request title** (`PR_TITLE`); release-please parses that title.
- Settings > Actions > General: allow GitHub Actions to create and approve pull requests (release-please opens the release PR with `GITHUB_TOKEN`).

## Maintainer Checklist

Before merging a normal PR:

1. PR title is a valid conventional commit.
2. Merge method is **Squash and merge**.

Before merging an adapter release PR:

1. Version bump matches the commits since the last release.
2. `CHANGELOG.md` and `deploy/chart/Chart.yaml` (`appVersion`) both show the new version.
3. Merge method is **Squash and merge**.
4. After merge, the `Release Please` workflow completes and the release notes include the image references.
5. Keep `release-as` **absent** from `.release-please/config-adapter.json`. It is permanent, not one-shot: every later release would repeat the same version.

Before merging a chart release PR:

1. It is labelled `chart-release: pending` and titled `chore: release chart X.Y.Z`.
2. It touches exactly three files: `deploy/chart/CHANGELOG.md`, `deploy/chart/Chart.yaml` (`version`) and `deploy/chart/README.md` (the cosign example). A release PR that does not touch `README.md` means the `x-release-please-start-version` markers broke; fix the markers before merging.
3. `Chart.yaml` `appVersion` points at an adapter version that is **already published** as an image. The chart publish job does not wait on an image build. After an adapter release the chart changelog shows `release adapter X.Y.Z` under Miscellaneous; that entry is expected.
4. Keep `release-as` **absent** from `.release-please/config-chart.json`. It is permanent, not one-shot: every later chart release would repeat the same version.
5. Merge method is **Squash and merge**.
6. After merge, the `chart-vX.Y.Z` tag exists, the GitHub Release is published and non-draft, `Publish Helm Chart` succeeds, and the release notes gained an `## Install` section carrying the resolved `appVersion` and the chart `cosign verify` command.
7. Verify the published chart end to end: `helm pull oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair --version X.Y.Z`, `cosign verify` against `publish-chart.yml@refs/heads/main`, and `oras manifest fetch 8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:artifacthub.io`.
8. Confirm the chart appears on artifacthub.io within a scrape cycle, and shows the verified-publisher badge once `repositoryID` is set.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
