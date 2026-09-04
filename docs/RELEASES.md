# Release Process

Releases are automated with [release-please](https://github.com/googleapis/release-please). Do not create `v*` tags, or GitHub Releases, manually.

There is **one release line** today, with its own release-please instance,
config, manifest, changelog and tag namespace. The Helm chart gets a second,
independent line when it ships.

| Line | Covers | Tag | Config / manifest | Changelog |
|------|--------|-----|-------------------|-----------|
| Adapter | everything except `deploy/`, `.github/`, `docs/`, `taskfile/`, `.release-please/` | `vX.Y.Z` | `.release-please/config-adapter.json` / `.release-please/manifest-adapter.json` | `CHANGELOG.md` |
| Helm chart *(not shipped yet)* | `deploy/chart/` | `chart-vX.Y.Z` | `.release-please/config-chart.json` / `.release-please/manifest-chart.json` | `deploy/chart/CHANGELOG.md` |

The chart row lands together with the chart. The adapter line already ignores
`deploy/`, so nothing has to change here when it does. They stay separate so a
chart fix does not force an adapter release that republishes an identical image,
and an adapter release does not republish the chart by itself.

Release state is defined by:

- Conventional squash commit titles on `main`
- `.release-please/config-adapter.json` and `.release-please/manifest-adapter.json` (the manifest holds the last published version)
- `CHANGELOG.md`

The manifest starts at `1.1.1`, continuing the version line the upstream project
published on Docker Hub for the same adapter. The matching tag does not exist in
this fork; that is harmless because `bootstrap-sha` supplies the history floor.
It is inclusive, so commits at or before it are ignored: it is pinned to the last
commit of the fork's infrastructure port, which keeps the 44 upstream commits
below it, several of them conventional, out of `CHANGELOG.md`. Upstream's own
releases are linked from the top of that file instead.

## How It Works

1. PRs are squash-merged to `main` with conventional commit titles. The PR title becomes the commit release-please parses, so the repository must allow **squash merging only** (disable merge commits and rebase merging).
2. On every push to `main`, the `Release Please` workflow opens or updates a `chore: release adapter X.Y.Z` PR whenever there are releasable commits. That PR bumps `.release-please/manifest-adapter.json` and updates `CHANGELOG.md`.
3. Squash-merging the release PR creates the `vX.Y.Z` tag and the GitHub Release.
4. The release then automatically:
   - builds and pushes the multi-arch (`linux/amd64`, `linux/arm64`) image `8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z`
   - signs the image with cosign (keyless) and attaches an SPDX SBOM attestation
   - uploads the adapter binaries as release assets
   - appends image references and cosign verification commands to the release notes

Every push to `main` additionally publishes `8gears.container-registry.com/8gcr/harbor-scanner-clair:latest` via the `Main Image` workflow.

## Version Rules

A release PR opens as soon as there is at least one commit of a type that is
shown in the changelog. Hidden types never open a release on their own. The
bump is decided by the highest-ranking commit: breaking > `feat:` > everything
else.

| Commit type | Bump | Notes section |
|-------------|------|---------------|
| `feat!:` or `BREAKING CHANGE:` | Major | Breaking changes |
| `feat:` | Minor | Features |
| `fix:` | Patch | Bug Fixes |
| `perf:`, `upstream:`, `revert:`, `refactor:`, `docs:` | Patch | Performance Improvements, Upstream, Reverts, Code Refactoring, Documentation |
| `chore:`, `ci:`, `build:`, `test:` | Hidden, no release | - |

Use `upstream:` for changes synced from `goharbor/harbor-scanner-clair`. The
cherry-pick workflow writes that type into the PR title for you.

Which line a commit lands on is decided by its paths: the adapter line ignores
`.github/`, `docs/`, `deploy/`, `taskfile/` and `.release-please/`. Use `ci:` for
workflow-only changes.

Once the chart exists, scope chart commits `feat(chart):` / `fix(chart):` and
keep them inside the paths the adapter ignores. One file outside, even
`README.md`, puts the commit in the adapter changelog and bumps the adapter
version. When `exclude-paths` in `.release-please/config-adapter.json` changes,
update the `Chart Scope Paths` check's patterns to match.

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
dependabot keeps gomod and github-actions. The tooling pins get Renovate's
default `chore(deps):`, which the adapter line hides. `TYPOS_VERSION` is
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
| Adapter binaries | `scanner-clair_linux-{amd64,arm64}.tar.gz` release assets |
| Checksums | `checksums.txt` release asset (SHA256 of all tarballs) |
| Changelog | `CHANGELOG.md` and the GitHub Release |

Verify an image signature:

```sh
cosign verify \
  --certificate-identity "https://github.com/container-registry/harbor-scanner-clair/.github/workflows/publish-image.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  8gears.container-registry.com/8gcr/harbor-scanner-clair:vX.Y.Z
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

There is no registry password anywhere: publish jobs authenticate keyless through
Harbor's Federated Identity Provider. The job mints a GitHub OIDC token
(`id-token: write`, audience `https://<registry>`), logs in with `-u jwt` and the
token as password, and Harbor maps it to the federated robot
`robot_gh-scanner-clair-push` via a claim rule that only matches this repository's
tokens (`repository == container-registry/harbor-scanner-clair`). The robot has no
secret; there is nothing to rotate or leak. See
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
2. `CHANGELOG.md` shows the new version.
3. Merge method is **Squash and merge**.
4. After merge, the `Release Please` workflow completes and the release notes include the image references.
5. Keep `release-as` **absent** from `.release-please/config-adapter.json`. It is permanent, not one-shot: every later release would repeat the same version.

## Manual Intervention

Manual intervention should be rare:

- Rerun a failed release workflow job.
- Never push replacement tags or edit published releases unless maintainers agree the release is unrecoverable.
