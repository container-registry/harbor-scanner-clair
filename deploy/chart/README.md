# harbor-scanner-clair

A production-ready Helm chart for the Harbor Scanner Adapter for Clair - the vulnerability scanner adapter that fronts an external Clair 4.x (Project Quay).

The adapter implements Harbor's scanner adapter API: Harbor posts a scan
request, the adapter submits the image manifest to Clair's indexer
(`POST /indexer/api/v1/index_report`), Clair fetches the layers itself, and the
adapter reads the rolled-up report from
`GET /matcher/api/v1/vulnerability_report/{digest}` and transforms it into a
Harbor vulnerability report stored in PostgreSQL.

> **This is a vulnerability-only adapter: no SBOM.** Do not make it Harbor's
> system default scanner - Harbor derives its registry-wide Security Hub numbers
> from the default scanner's capabilities, and an adapter that produces no SBOM
> zeroes them. Register it and use it per project.

## Prerequisites

- Kubernetes >= 1.28
- **A Clair 4.9+ server you operate**, reachable at `clair.url`. This chart
  deploys none; see [`example/external-clair/`](example/external-clair/). If it
  uses pre-shared-key authentication, `clair.jwtIssuer` must appear in its
  `auth.psk.iss` list and `clair.psk` must carry the same key.
- **A network route from Clair to Harbor's registry.** Clair pulls the layer
  blobs itself, so a NetworkPolicy or DNS problem in Clair's namespace stops
  every scan even when the adapter is healthy.
- **A PostgreSQL database for the adapter**, named by `postgres.url` or
  `postgres.existingSecret`. Clair's own PostgreSQL server is the usual choice,
  in a database of its own (`scanner`): the adapter creates a single `scan_job`
  table there at startup, so the role in the connection string needs the right
  to create it. This chart deploys no database either; `example/external-clair/`
  creates both.
- A Harbor >= 2.2 to register the scanner with.

## Install

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor --create-namespace \
  --set clair.url=http://clair.clair.svc:6060 \
  --set postgres.existingSecret=harbor-scanner-clair-postgres
```

Then register the scanner in Harbor under **Administration -> Interrogation
Services -> Scanners -> NEW SCANNER**, using the endpoint the chart prints on
install:

```
http://harbor-scanner-clair.harbor.svc:8080
```

The default connection string assumes Clair's PostgreSQL next door
(`postgres://clair@clair-postgres:5432/scanner?sslmode=disable`), which has no
password in it and therefore works for almost nobody. Point `postgres.url` at
yours, or better, keep the whole DSN in a Secret you own and name it with
`postgres.existingSecret`. Either way the chart hands it to the container as a
`secretKeyRef`; a DSN set in values is written to the chart-managed Secret
rather than into the pod spec.

## What this chart gives you

- **Secrets stay yours.** Every credential has an `existingSecret` form - the
  Clair pre-shared key, the store connection string, the TLS keypair - so
  nothing sensitive has to live in a values file or in Git.
- **Deterministic renders.** Nothing is generated at render time, so Argo CD and
  Flux see no drift. CI renders the GitOps values twice and fails on any diff.
- **Fail-fast validation.** A closed `values.schema.json` rejects unknown or
  malformed keys, and render-time guards catch the cross-field mistakes a schema
  cannot express - TLS enabled with no certificate, a PDB with no budget, a
  pre-shared key that is both inlined and externally owned. They fail
  `helm template`, not the cluster.
- **Probes as data.** The full Kubernetes probe specs are values. The chart
  injects `scheme: HTTPS` when you turn TLS on.
- **The whole production surface.** ServiceAccount, PodDisruptionBudget, HPA,
  ServiceMonitor, NetworkPolicy, scheduling constraints, sidecars, init
  containers, and `extraManifests` - independently switchable, and off by
  default except the dedicated ServiceAccount, which is created for you.
- **No dead ends.** Every adapter setting is reachable through `config` /
  `secret` without a chart change, and every Kubernetes field the chart does not
  template is reachable through the merge hatches below.

## Configuring the adapter

The adapter is configured entirely by environment variables, so `config` reaches
all of it - including settings added after this chart version:

```yaml
config:
  scanner:
    clair:
      report_retry_timeout: 10m
    store:
      scan_job_ttl: 4h
    log:
      level: debug
```

Nested keys join with `_` and are uppercased, lists join with `,`, so that
renders `SCANNER_CLAIR_REPORT_RETRY_TIMEOUT`, `SCANNER_STORE_SCAN_JOB_TTL` and
`SCANNER_LOG_LEVEL` into a ConfigMap consumed with `envFrom`. No prefix is imposed, so `HTTP_PROXY` and friends are
reachable the same way.

`secret` takes the identical notation but renders into a Secret, so the values
never enter the pod spec. Credential-shaped keys in `config` are refused at
render time. The adapter's optional API key has no chart value of its own for
that reason - set it through `secret`:

```yaml
secret:
  scanner:
    api:
      auth:
        api_key: a-long-random-string
```

Harbor then has to send it as `X-ScannerAdapter-API-Key` on every
`/api/v1/*` call.

Precedence, lowest to highest:

```
chart defaults  <  config / secret  <  extraEnv
```

Kubernetes evaluates `envFrom` before `env`, so a chart-set variable would
otherwise beat your `config`. The chart drops its own entry for any name you
claim, which is what makes the middle of that chain work.

## Escape hatches

The chart cannot template every field of a Deployment. Three deep-merge hooks
cover what it does not expose, and yours wins on conflict:

| Value | Merges into | For example |
|-------|-------------|-------------|
| `deploymentSpecOverrides` | `.spec` | `minReadySeconds`, `progressDeadlineSeconds`, `paused` |
| `podSpecOverrides` | `.spec.template.spec` | `runtimeClassName`, `hostNetwork`, `enableServiceLinks`, `nodeName` |
| `containerOverrides` | the adapter container | `workingDir`, `terminationMessagePolicy`, `resizePolicy` |

The merge only runs when one is set, so the default render stays in template
order; opting in re-marshals the object (sorted keys, still deterministic).
`extraManifests` covers anything that is a separate object rather than a field.

## Sizing

The adapter holds neither vulnerability data nor layer bytes. It builds a
manifest, waits on one synchronous index call, and turns the answer into a
Harbor report; the database, the layer fetching and the matching all live in the
Clair server. So:

- **Concurrency is `replicaCount * jobQueue.workerConcurrency`.** That product
  is how many scans can be in flight, and the adapter is the only thing rate
  limiting Clair: Harbor's Scan All issues scan requests without a cap.
- **Clair's indexer has its own limit.** Above its
  `index_report_request_concurrency` it answers 429, and the adapter surfaces
  that as a failed scan. Lower `jobQueue.workerConcurrency` or raise Clair's
  limit; do not treat 429 as a reason to retry harder.
- **Memory scales with reports in flight**, one report per in-flight scan, not
  with image size.
- **Jobs are durable.** The queue is the `scan_job` table: a worker claims a
  row under a lock, and a worker that dies has its row reclaimed once the lock
  expires. On SIGTERM it drains its in-flight scans instead, bounded at 10
  seconds, so `terminationGracePeriodSeconds` above that only bounds the
  kubelet's wait.
- **Connections scale with replicas.** Each replica opens its own pool, five
  connections by default, so `replicaCount` multiplies straight into the
  database's `max_connections`.

## TLS

`api.tls.enabled` switches the listener to HTTPS; Harbor must then be registered
with an `https://` endpoint and must trust the issuing CA. Prefer
`api.tls.existingSecret` - it takes a cert-manager `Certificate` Secret
directly. See [`example/tls-cert-manager/`](example/tls-cert-manager/).

There is no mutual TLS: the adapter never verifies client certificates. Use
`networkPolicy.ingress` to restrict who may call it.

For **outbound** trust - a registry, PostgreSQL or Clair behind a private CA - use
`extraCA`, see [`example/private-ca/`](example/private-ca/).
`tls.insecureSkipVerify` turns verification off for all of them at once and is
a much blunter instrument.

## Verifying the chart signature

Chart releases are cosign-signed keylessly by the release workflow, with no
long-lived key to manage:

<!-- x-release-please-start-version -->
```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/container-registry/harbor-scanner-clair/\.github/workflows/publish-chart\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:0.1.0
```
<!-- x-release-please-end -->

Flux can enforce the same check on every reconcile - see
[`example/flux/`](example/flux/).

## Troubleshooting

**The scanner shows as unhealthy in Harbor.** Harbor calls `/api/v1/metadata`.
Check the adapter answers from inside the cluster, then check Harbor can reach
that exact URL - a TLS-enabled adapter registered with an `http://` endpoint
fails here, and so does an `https://` endpoint whose CA Harbor does not trust.

```sh
kubectl -n harbor exec deploy/harbor-scanner-clair -- \
  wget -qO- http://localhost:8080/api/v1/metadata
```

**Every scan stays pending right after install.** Clair's matcher answers 202
with an empty body until its first updater cycle has put something in its
vulnerability table. Check Clair's logs, not the adapter's. The same condition
keeps the adapter unready, because `/probe/ready` asks Clair that question.

**The pod stays unready.** `/probe/ready` pings the database and then asks Clair's
matcher for a report on the all-zeroes digest: 202 means Clair has no
vulnerability data yet, 404 means it has some. Note what that proves and what it
does not - the vulnerability table is non-empty, which is neither "the update
cycle finished" nor "CVSS enrichment is loaded", so scores can be missing for
another minute or two after the pod goes ready.

**Scans fail with a 404 from Clair.** The matcher answers 404 while the index
report is missing or has not reached `IndexFinished`. It is not permanent: it
means indexing did not complete, so look at why the index call failed.

**Scans fail with 429.** Clair's indexer rate-limits concurrent index requests
(`index_report_request_concurrency`, auto-sized to `GOMAXPROCS*4`). Lower
`jobQueue.workerConcurrency`, or raise Clair's limit.

**Every Clair call is 401.** Either `clair.jwtIssuer` does not appear in Clair's
`auth.psk.iss` list, or the key does not match. Both sides take the key
base64-encoded, and `clair.psk` is that base64 text verbatim.

The adapter names the failing dependency and the error category in its own logs:

```sh
kubectl -n harbor logs deploy/harbor-scanner-clair | grep -i "clair\|postgres"
```

**Scans stay pending forever.** The report lives in the `scan_job` row, and
Harbor polls for it. A wrong host, a wrong database or a password that never
arrived all look the same from Harbor. Note also that a report expires after
`store.scanJobTTL` (default `1h`) whether Harbor collected it or not.

**The pod exits at startup complaining about the store.** The adapter opens the
pool and runs `CREATE TABLE IF NOT EXISTS scan_job` before it serves anything,
so a role that can only read and write an existing table is not enough on a
fresh database, and a database that does not exist at all fails here rather than
on the first scan.

**`x509: certificate signed by unknown authority`.** The registry, PostgreSQL
or Clair is behind a private CA. Use `extraCA` - see
[`example/private-ca/`](example/private-ca/). Do not reach for
`tls.insecureSkipVerify`, which disables verification everywhere.

**The adapter will not start, naming a root CA pool.** `extraCA.keys` names a
file that is absent from the Secret or ConfigMap, or that is not PEM. The
adapter reads every path in `SCANNER_TLS_CLIENTCAS` at startup and refuses to
run if one cannot be appended.

**A values key stopped working after an upgrade.** The schema root is closed, so
an unknown key fails the render by name. A values file written for the Trivy
adapter fails the same way, by design.

## Uninstalling

```sh
helm uninstall harbor-scanner-clair --namespace harbor
```

Nothing is left behind: the chart provisions no PersistentVolumeClaims. The
`scan_job` table stays in your database - drop it, or the whole `scanner`
database, once nothing polls for those reports. Index reports stay in Clair's own
database - the adapter deliberately never deletes them, because Clair's storage
is content-addressed and shared across manifests, so per-scan deletion would
destroy the re-index fast path. Remove the scanner registration in Harbor as
well, or it keeps pointing at a Service that no longer exists.

## Examples

See [`example/`](example/) - standing up a Clair 4.x backend with the adapter's
database next to it, Harbor integration, cert-manager TLS, FluxCD, OpenShift and
private CAs. CI renders all of them on every change.

## Migrating

[`docs/FROM-KUBE-MANIFESTS.md`](docs/FROM-KUBE-MANIFESTS.md) maps the raw
manifests this repository shipped until adapter 2.0.0 onto chart values, and
lists the environment changes between adapter 1.x and 2.0.0.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| 8gears | <vadim@8gears.com> | <https://github.com/container-registry/harbor-scanner-clair> |

## Source Code

* <https://github.com/container-registry/harbor-scanner-clair>

## Requirements

Kubernetes: `>=1.28.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod assignment. |
| api.idleTimeout | string | `"60s"` | Idle timeout for keep-alive connections. |
| api.readTimeout | string | `"15s"` | Maximum duration for reading an entire request, including the body. |
| api.tls.certificate | string | `""` | PEM certificate, inlined into a chart-managed Secret. Ignored when `existingSecret` is set. |
| api.tls.enabled | bool | `false` | Serve the adapter API over HTTPS. Harbor must then register the scanner with an `https://` URL. The adapter does not verify client certificates, so this is server TLS only. |
| api.tls.existingSecret | string | `""` | Existing `kubernetes.io/tls` Secret holding `tls.crt` and `tls.key`. Preferred over inlining PEM in values; works directly with a cert-manager Certificate. Required unless `certificate`/`key` are set. |
| api.tls.key | string | `""` | PEM private key, inlined into a chart-managed Secret. Ignored when `existingSecret` is set. |
| api.writeTimeout | string | `"15s"` | Maximum duration before timing out a response write. This bounds a single HTTP response, not a scan. |
| autoscaling.behavior | object | `{}` | Scaling behavior. |
| autoscaling.enabled | bool | `false` | Create a HorizontalPodAutoscaler. |
| autoscaling.maxReplicas | int | `5` | Maximum replicas. |
| autoscaling.metrics | list | `[]` | Extra metrics appended to the generated ones. |
| autoscaling.minReplicas | int | `1` | Minimum replicas. |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target average CPU utilization, in percent. `null` drops the metric. |
| autoscaling.targetMemoryUtilizationPercentage | string | `nil` | Target average memory utilization, in percent. `null` drops the metric. |
| clair.existingSecret | string | `""` | Existing Secret holding the base64 pre-shared key. Mutually exclusive with `psk`, and keeps the key out of the pod spec. |
| clair.existingSecretKey | string | `"psk"` | Key within `clair.existingSecret`. |
| clair.indexTimeout | string | `"10m"` | Deadline for one `POST /indexer/api/v1/index_report`. Indexing is synchronous: Clair pulls every layer and scans it inside this one request, so this bounds the whole fetch-and-index phase, not a round trip. |
| clair.jwtIssuer | string | `"harbor-scanner-clair"` | `iss` claim the adapter puts in its JWT. Clair rejects a token whose issuer is not in its `auth.psk.iss` list, so this must appear there. |
| clair.psk | string | `""` | Pre-shared key for Clair's JWT authentication, base64 as Clair's own `auth.psk.key` takes it. The adapter signs an HS256 token with the decoded bytes and sends it as `Authorization: Bearer`. Leave empty for a Clair with no `auth` stanza; a Clair that has one answers 401 without it. Prefer `existingSecret`. |
| clair.requestTimeout | string | `"30s"` | Deadline for every other Clair call (vulnerability report, updater state). |
| clair.url | string | `"http://clair:6060"` | Base URL of the Clair 4.x API. The adapter POSTs a manifest to `/indexer/api/v1/index_report` and reads `/matcher/api/v1/vulnerability_report/{digest}` back. This chart does not deploy Clair; see `example/external-clair/`. |
| commonAnnotations | object | `{}` | Annotations added to every rendered object. |
| commonLabels | object | `{}` | Labels added to every rendered object. |
| config | object | `{}` | Adapter configuration as a nested map, flattened into env vars in a chart-managed ConfigMap and consumed with `envFrom`. Nested keys join with `_` and are uppercased; lists join with `,`:      config:       scanner:         clair:           index_timeout: 20m   ->   SCANNER_CLAIR_INDEX_TIMEOUT=20m  The adapter is configured entirely by environment, so this reaches every setting it has - including ones added after this chart version, with no chart change. The chart drops its own entry for any name claimed here, because `envFrom` would otherwise lose to it.  A ConfigMap is not secret. Credential-shaped keys are refused at render time; put them in `secret` below - `secret.scanner.api.auth.api_key` is how the optional `SCANNER_API_AUTH_API_KEY` is set, since the chart has no value for it. |
| containerOverrides | object | `{}` | Deep-merged into the adapter container, for fields the chart does not template (`workingDir`, `terminationMessagePolicy`, `resizePolicy`). Sidecars are untouched. Yours wins on conflict. |
| deploymentAnnotations | object | `{}` | Annotations on the Deployment object itself (not its pods). For controllers that key off the workload, such as Argo CD sync waves. Pod annotations are `podAnnotations`; annotations for every object are `commonAnnotations`. |
| deploymentSpecOverrides | object | `{}` | Deep-merged into the Deployment `.spec`, for fields the chart does not template (`minReadySeconds`, `progressDeadlineSeconds`, `paused`). Yours wins on conflict. |
| dnsConfig | object | `{}` | Pod DNS config. |
| dnsPolicy | string | `""` | Pod DNS policy. |
| extraCA | object | `{"existingConfigMap":"","existingSecret":"","keys":[]}` | Private CA certificates to trust, on top of the system bundle. The adapter is a Go program, so this covers every outbound TLS call it makes: pulling image manifests from a registry with an internal CA, a Postgres reached with `sslmode=verify-full`, an HTTPS Clair endpoint. It does not cover Clair's own pulls from the registry; Clair's trust store is configured in Clair.  Two mechanisms are set up together, deliberately. The bundle is mounted at `/etc/scanner-clair/extra-ca` and `SSL_CERT_DIR=/etc/ssl/certs:/etc/scanner-clair/extra-ca` is set, which covers a whole-bundle mount with `keys: []`; the system path is listed explicitly on purpose, because Go replaces its default directory list when `SSL_CERT_DIR` is set. Naming `keys` additionally emits `SCANNER_TLS_CLIENTCAS`, the adapter's own list of PEM files to append to the system pool. |
| extraCA.existingConfigMap | string | `""` | Existing ConfigMap holding one or more PEM certificates. Mutually exclusive with `existingSecret`. |
| extraCA.existingSecret | string | `""` | Existing Secret holding one or more PEM certificates. Takes a cert-manager CA Secret directly. |
| extraCA.keys | list | `[]` | Keys to mount from it. Empty mounts every key and relies on `SSL_CERT_DIR`; naming keys also puts them in `SCANNER_TLS_CLIENTCAS`. |
| extraEnv | list | `[]` | Extra environment variables, in full `EnvVar` form (so `valueFrom` works). Appended last, so a name set here wins over both `config`/`secret` and the chart's own entry. Full precedence, lowest to highest: chart defaults < config / secret < extraEnv. |
| extraEnvFrom | list | `[]` | Extra `envFrom` sources (ConfigMap/Secret references). |
| extraManifests | list | `[]` | Extra raw manifests rendered with the release. Strings are passed through `tpl`, so they may reference `.Values` and `.Release`. |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the adapter container. |
| extraVolumes | list | `[]` | Extra volumes for the adapter pod. |
| fullnameOverride | string | `""` | Override the fully qualified resource name (`<release>-<chart>`). |
| global | object | `{"imagePullSecrets":[],"imageRegistry":""}` | Values shared across the chart (and any future subchart). |
| global.imagePullSecrets | list | `[]` | Image pull secrets applied to every pod in the chart. |
| global.imageRegistry | string | `""` | Registry override applied to every image in the chart. Wins over `image.registry`; the repository path is preserved. Set this to point an air-gapped install at a mirror in one place. |
| hostAliases | list | `[]` | Additional host aliases injected into `/etc/hosts`. |
| image.digest | string | `""` | Image digest (`sha256:...`). Wins over `tag` when set; pin this for immutable, GitOps-friendly deployments. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.pullSecrets | list | `[]` | Image pull secrets for this image, merged with `global.imagePullSecrets`. |
| image.registry | string | `"8gears.container-registry.com"` | Image registry. |
| image.repository | string | `"8gcr/harbor-scanner-clair"` | Image repository. |
| image.tag | string | `.Chart.AppVersion` | Image tag. |
| imageCredentials | object | `{"create":false,"email":"","password":"","registry":"","username":""}` | Build a `dockerconfigjson` pull Secret from inline credentials, for installs with no pre-existing one to reference. Prefer `image.pullSecrets` with a Secret you own: the password set here is stored in the release. |
| imageCredentials.create | bool | `false` | Create the Secret and add it to the pod's `imagePullSecrets`. |
| imageCredentials.email | string | `""` | Registry account email, which some registries still require. |
| imageCredentials.password | string | `""` | Registry password or token. |
| imageCredentials.registry | string | `global.imageRegistry`, else `image.registry` | Registry the credentials are for. |
| imageCredentials.username | string | `""` | Registry username. |
| initContainers | list | `[]` | Init containers, passed through `tpl`. |
| jobQueue.workerConcurrency | int | `1` | Workers per replica. Harbor's Scan All issues unbounded concurrent scan requests (its job `MaxCurrency()` is 0), so the adapter is the only thing rate-limiting Clair. Scale with `replicaCount` rather than this: Clair's indexer returns 429 above its own `index_report_request_concurrency`, and each in-flight scan holds a manifest and a report in adapter memory. |
| lifecycle | object | `{}` | Container lifecycle hooks. |
| logLevel | string | `"info"` | Adapter log level: `trace`, `debug`, `info`, `warn`, `warning`, `error`. Anything unrecognized falls back to `info`. |
| metrics.enabled | bool | `true` | Serve Prometheus metrics on `/metrics` of the API port (`SCANNER_API_SERVER_METRICS_ENABLED`). |
| metrics.serviceMonitor.annotations | object | `{}` | Extra annotations. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. Requires the `monitoring.coreos.com/v1` CRD and `metrics.enabled`. |
| metrics.serviceMonitor.honorLabels | bool | `false` | Honor labels exposed by the target. |
| metrics.serviceMonitor.interval | string | `""` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels, e.g. the `release` label your Prometheus selects on. |
| metrics.serviceMonitor.metricRelabelings | list | `[]` | Relabeling rules applied to scraped samples. |
| metrics.serviceMonitor.namespace | string | `""` | Namespace for the ServiceMonitor. Defaults to the release namespace. |
| metrics.serviceMonitor.relabelings | list | `[]` | Relabeling rules applied before scraping. |
| metrics.serviceMonitor.scrapeTimeout | string | `""` | Scrape timeout. |
| metrics.serviceMonitor.tlsConfig | object | `{}` | TLS config used when scraping a TLS-enabled adapter. |
| nameOverride | string | `""` | Override the chart name used in resource names and labels. |
| networkPolicy.egress | list | `[]` | Egress rules, used when `networkPolicy.egressEnabled` is set. |
| networkPolicy.egressEnabled | bool | `false` | Restrict egress as well. Leave off unless you enumerate Postgres, the Clair API and the registry in `networkPolicy.egress`. Clair pulls the blobs itself, so the adapter's own registry egress is manifest traffic only - but Clair's namespace then needs a policy that lets Clair reach the registry. |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy for the adapter pods. |
| networkPolicy.ingress | list | `[]` | Peers allowed to reach the API port. Empty allows any source; set this to the Harbor core/jobservice selectors to lock the adapter down. |
| nodeSelector | object | `{}` | Node labels for pod assignment. |
| podAnnotations | object | `{}` | Annotations added to the adapter pods. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. Only useful with `replicaCount` > 1. |
| podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable pods. Mutually exclusive with `minAvailable`. |
| podDisruptionBudget.minAvailable | string | `""` | Minimum available pods. Mutually exclusive with `maxUnavailable`. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `"AlwaysAllow"` | `unhealthyPodEvictionPolicy` (Kubernetes >= 1.27). `AlwaysAllow` so a wedged adapter pod cannot block a node drain: an unready scan worker is not serving anyone, and holding the budget open for it only stalls the cluster. |
| podLabels | object | `{}` | Labels added to the adapter pods. |
| podSecurityContext | object | `{"fsGroup":10000,"runAsGroup":10000,"runAsNonRoot":true,"runAsUser":10000,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level security context. The image creates the `scanner` user at UID/GID 10000 and owns `/home/scanner` with it. |
| podSpecOverrides | object | `{}` | Deep-merged into the pod spec, for fields the chart does not template (`runtimeClassName`, `hostNetwork`, `enableServiceLinks`, `nodeName`, `shareProcessNamespace`, `readinessGates`). Yours wins on conflict. |
| postgres | object | `{"existingSecret":"","existingSecretKey":"url","url":"postgres://clair@clair-postgres:5432/scanner?sslmode=disable"}` | Where the adapter keeps its scan jobs and reports. This is Clair's own PostgreSQL instance by default, in a **separate database** (`scanner`): the adapter never touches Clair's own tables, and Clair's migrations never see the adapter's. The chart deploys no database; `example/external-clair/` creates both. |
| postgres.existingSecret | string | `""` | Existing Secret holding the complete DSN. Wins over `url`, and keeps the password out of the release as well as out of the pod spec. |
| postgres.existingSecretKey | string | `"url"` | Key within `postgres.existingSecret`. |
| postgres.url | string | `"postgres://clair@clair-postgres:5432/scanner?sslmode=disable"` | Connection string, `postgres://user:password@host:5432/scanner?sslmode=...`. The chart always reads it through a Secret - a DSN set here is written to the chart-managed Secret rather than into the pod spec - but it still lands in the release, so prefer `existingSecret` outside a test install.  The role in the DSN owns the adapter's table: the adapter runs `CREATE TABLE IF NOT EXISTS scan_job ...` at startup, so it needs create rights on the database, not only DML on an existing table. |
| priorityClassName | string | `""` | PriorityClass for the adapter pods. |
| probes | object | `{"liveness":{"failureThreshold":10,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"readiness":{"failureThreshold":3,"httpGet":{"path":"/probe/ready","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"startup":{"failureThreshold":15,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":2,"timeoutSeconds":3}}` | Container probes, passed through verbatim. The chart fills in `scheme: HTTPS` when `api.tls.enabled` is set and no scheme is given. Set a probe to `null` to drop it. `/probe/ready` is a real check: it pings Postgres and asks Clair's matcher whether it holds any vulnerability data, so a pod stays unready while either is missing. `/probe/healthy` is unconditional. |
| proxy.httpProxy | string | `""` | HTTP proxy URL. |
| proxy.httpsProxy | string | `""` | HTTPS proxy URL. |
| proxy.noProxy | string | `""` | Comma-separated hosts the proxy settings do not apply to. Postgres, the Clair 4.x API and the Harbor registry normally belong here. |
| replicaCount | int | `1` | Number of adapter replicas. The adapter holds no local state: the reports live in Postgres, and the vulnerability data and the layer fetching both live in Clair. Replicas buy availability and scan throughput alike. |
| resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Resource requests and limits. The adapter never fetches a layer blob: it builds a manifest, waits on one synchronous index call, and transforms a JSON report. Memory scales with report size and `jobQueue.workerConcurrency`, not with image size. |
| revisionHistoryLimit | int | `10` | Deployment revision history retained for rollbacks. |
| schedulerName | string | `""` | Alternative scheduler for the adapter pods. |
| secret | object | `{}` | Same notation as `config`, rendered into a chart-managed Secret instead, so the values never appear in the pod spec. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true}` | Container-level security context. The adapter writes only to `/tmp`, which is mounted, so the root filesystem stays read-only. |
| service.annotations | object | `{}` | Annotations for the Service. |
| service.clusterIP | string | `""` | Static cluster IP. |
| service.externalTrafficPolicy | string | `""` | External traffic policy. |
| service.ipFamilies | list | `[]` | IP families for the Service, e.g. `[IPv4, IPv6]`. Empty follows the cluster default. |
| service.ipFamilyPolicy | string | `""` | IP family policy: `SingleStack`, `PreferDualStack` or `RequireDualStack`. |
| service.labels | object | `{}` | Labels for the Service. |
| service.loadBalancerSourceRanges | list | `[]` | Load balancer source ranges. |
| service.nodePort | string | `""` | NodePort, when `service.type` is `NodePort` or `LoadBalancer`. |
| service.port | int | `8080` | Service port. Also the port the adapter listens on. |
| service.sessionAffinity | string | `""` | Session affinity. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | Annotations for the created ServiceAccount (IRSA, Workload Identity). |
| serviceAccount.automountServiceAccountToken | bool | `false` | Mount the ServiceAccount token into the pod. The adapter never calls the Kubernetes API, so this stays off. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the adapter. |
| serviceAccount.name | string | the fullname template | Name of the ServiceAccount to use. |
| sidecars | list | `[]` | Sidecar containers, passed through `tpl`. |
| store.backend | string | `"postgres"` | Where scan jobs and reports live: `postgres` or `memory`. `memory` is for a single-replica development install only - nothing survives a restart and two replicas share no state, so Harbor polls a report the other pod holds. The chart refuses `memory` with more than one replica. |
| store.scanJobTTL | string | `"1h"` | TTL for persisted scan jobs and reports. A report is unreadable once it expires, so keep it comfortably above the time Harbor takes to collect one, and above `clair.indexTimeout` plus the time a job spends queued. |
| strategy | object | `{}` | Deployment update strategy. Empty means the Kubernetes default (`RollingUpdate`, 25% surge and unavailable). |
| terminationGracePeriodSeconds | int | `60` | Grace period for a terminating pod. On SIGTERM the worker stops taking new jobs and waits up to 10 seconds for the in-flight ones, so anything above that only bounds how long the kubelet waits before SIGKILL. |
| tls.insecureSkipVerify | bool | `false` | Skip TLS verification on every outbound connection the adapter makes - the registry and Clair both. A blunt instrument; for a private CA use `extraCA` instead. |
| tolerations | list | `[]` | Tolerations for pod assignment. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints. |
