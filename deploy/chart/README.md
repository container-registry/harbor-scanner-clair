# harbor-scanner-clair

A production-ready Helm chart for the Harbor Scanner Adapter for Clair - the vulnerability scanner adapter that fronts an external CoreOS Clair 2.x.

The adapter implements Harbor's scanner adapter API: Harbor posts a scan
request, the adapter fetches the image manifest from the registry, posts each
layer to Clair's **v1** REST API, polls for the result, and transforms it into a
Harbor vulnerability report stored in Redis.

> **Clair 2.x is end of life, and this chart does not deploy it.** Harbor
> removed its bundled Clair in 2.2 (November 2020) and CoreOS Clair 2.x has
> been unmaintained since. The adapter speaks the Clair **v1** API only, not the
> 4.x indexer/matcher split, and it implements Harbor's adapter API **v1.0**:
> vulnerability reports, no SBOM. Do not make it Harbor's system default
> scanner - Harbor derives its registry-wide Security Hub numbers from the
> default scanner's capabilities. For a maintained backend, use the Trivy
> adapter.

## Prerequisites

- Kubernetes >= 1.28
- **A CoreOS Clair 2.x server you operate**, reachable at `clair.url`. Harbor
  ships none; see [`example/external-clair/`](example/external-clair/).
- A Redis reachable from the cluster. Harbor's own Redis is the usual choice;
  give the adapter its own database number (Harbor uses `0`-`4`).
- A Harbor >= 2.2 to register the scanner with.
- Optionally, Clair's PostgreSQL DSN (`clair.databaseUrl`), read for one query:
  the vulnerability database timestamp Harbor shows next to the scanner.

## Install

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor --create-namespace \
  --set clair.url=http://clair.clair.svc:6060
```

Then register the scanner in Harbor under **Administration -> Interrogation
Services -> Scanners -> NEW SCANNER**, using the endpoint the chart prints on
install:

```
http://harbor-scanner-clair.harbor.svc:8080
```

The defaults assume Harbor's own Redis at `redis://harbor-harbor-redis:6379`.
Point `redis.url` at yours, or read the whole URL out of a Secret with
`redis.existingSecret` (see [`example/external-redis/`](example/external-redis/)).

## What this chart gives you

- **Secrets stay yours.** Every credential has an `existingSecret` form - the
  Clair database DSN, the Redis URL (password included), the TLS keypair - so
  nothing sensitive has to live in a values file or in Git.
- **Deterministic renders.** Nothing is generated at render time, so Argo CD and
  Flux see no drift. CI renders the GitOps values twice and fails on any diff.
- **Fail-fast validation.** A closed `values.schema.json` rejects unknown or
  malformed keys, and render-time guards catch the cross-field mistakes a schema
  cannot express - TLS enabled with no certificate, a PDB with no budget, a
  Clair DSN that is both inlined and externally owned. They fail
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
      url: http://clair.clair.svc:6060
    store:
      redis:
        scan_job_ttl: 4h
    log:
      level: debug
```

Nested keys join with `_` and are uppercased, lists join with `,`, so that
renders `SCANNER_CLAIR_URL`, `SCANNER_STORE_REDIS_SCAN_JOB_TTL` and
`SCANNER_LOG_LEVEL` into a ConfigMap consumed with `envFrom`. No prefix is
imposed, so `HTTP_PROXY` and friends are reachable the same way.

`secret` takes the identical notation but renders into a Secret, so the values
never enter the pod spec. Credential-shaped keys in `config` are refused at
render time.

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

The adapter holds no vulnerability data. It fetches an image manifest, posts the
layers to Clair, and turns the answer into a Harbor report; the database, the
matching and the memory that goes with them live in the Clair server. So:

- **Scale for concurrency, not for data.** `replicaCount` and `autoscaling`
  raise how many scans can be in flight. Each in-flight scan holds a manifest
  and a report in memory, which is why the memory limit exists at all.
- **Clair is the bottleneck, and it is not in this chart.** A slow scan is
  almost always Clair fetching or matching, not the adapter.
- **There is no queue.** The worker pool starts one goroutine per request with
  no concurrency cap and no retries, and a pod restart loses every scan it was
  running. Harbor retries at its own level; size `terminationGracePeriodSeconds`
  with that in mind rather than expecting a drain.

## TLS

`api.tls.enabled` switches the listener to HTTPS; Harbor must then be registered
with an `https://` endpoint and must trust the issuing CA. Prefer
`api.tls.existingSecret` - it takes a cert-manager `Certificate` Secret
directly. See [`example/tls-cert-manager/`](example/tls-cert-manager/).

There is no mutual TLS: the adapter never verifies client certificates. Use
`networkPolicy.ingress` to restrict who may call it.

For **outbound** trust - a registry, Redis or Clair behind a private CA - use
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
  8gears.container-registry.com/8gcr/charts/harbor-scanner-clair:1.0.0
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

**The pod is Ready but every scan fails.** `/probe/ready` returns 200
unconditionally: it checks neither Redis nor Clair. Readiness proves the process
is up and nothing else. `/api/v1/metadata` is the real check, and the logs name
which dependency is missing.

```sh
kubectl -n harbor logs deploy/harbor-scanner-clair | grep -i "clair\|redis"
```

**Scans stay pending forever.** The report lives in Redis under
`store.redisNamespace`, and Harbor polls for it. Wrong URL, wrong database or a
password that never arrived all look the same from Harbor. Note also that a
report expires after `store.redisScanJobTTL` (default `1h`) whether Harbor
collected it or not.

**`x509: certificate signed by unknown authority`.** The registry, Redis or
Clair is behind a private CA. Use `extraCA` - see
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

Nothing is left behind: the chart provisions no PersistentVolumeClaims. Scan
reports stay in Redis until their TTL expires. Remove the scanner registration
in Harbor as well, or it keeps pointing at a Service that no longer exists.

## Examples

See [`example/`](example/) - standing up a Clair backend, Harbor integration,
external Redis, cert-manager TLS, FluxCD, OpenShift and private CAs. CI renders
all of them on every change.

## Moving from the `kube/` manifests

The repository's `kube/harbor-scanner-clair.yaml` is a raw Deployment and
Service. [`docs/FROM-KUBE-MANIFESTS.md`](docs/FROM-KUBE-MANIFESTS.md) maps each
of its environment variables onto a chart value.

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
| clair.databaseUrl | string | `""` | PostgreSQL DSN for Clair's own database. Used for exactly one query, the `updater/last` timestamp reported as the vulnerability database age in `/api/v1/metadata`. Scanning works without it. It carries a password, so prefer `existingSecret`. |
| clair.existingSecret | string | `""` | Existing Secret holding the PostgreSQL DSN. Mutually exclusive with `databaseUrl`, and keeps the password out of the pod spec. |
| clair.existingSecretKey | string | `"databaseUrl"` | Key within `clair.existingSecret`. |
| clair.url | string | `"http://harbor-harbor-clair:6060"` | Base URL of the Clair 2.x API the adapter posts layers to. This chart does not deploy Clair; Harbor stopped bundling it in 2.2, so the server is yours to operate. See `example/external-clair/`. |
| commonAnnotations | object | `{}` | Annotations added to every rendered object. |
| commonLabels | object | `{}` | Labels added to every rendered object. |
| config | object | `{}` | Adapter configuration as a nested map, flattened into env vars in a chart-managed ConfigMap and consumed with `envFrom`. Nested keys join with `_` and are uppercased; lists join with `,`:      config:       scanner:         clair:           url: http://clair:6060   ->   SCANNER_CLAIR_URL=http://clair:6060  The adapter is configured entirely by environment, so this reaches every setting it has - including ones added after this chart version, with no chart change. The chart drops its own entry for any name claimed here, because `envFrom` would otherwise lose to it.  A ConfigMap is not secret. Credential-shaped keys are refused at render time; put them in `secret` below. |
| containerOverrides | object | `{}` | Deep-merged into the adapter container, for fields the chart does not template (`workingDir`, `terminationMessagePolicy`, `resizePolicy`). Sidecars are untouched. Yours wins on conflict. |
| deploymentAnnotations | object | `{}` | Annotations on the Deployment object itself (not its pods). For controllers that key off the workload, such as Argo CD sync waves. Pod annotations are `podAnnotations`; annotations for every object are `commonAnnotations`. |
| deploymentSpecOverrides | object | `{}` | Deep-merged into the Deployment `.spec`, for fields the chart does not template (`minReadySeconds`, `progressDeadlineSeconds`, `paused`). Yours wins on conflict. |
| dnsConfig | object | `{}` | Pod DNS config. |
| dnsPolicy | string | `""` | Pod DNS policy. |
| extraCA | object | `{"existingConfigMap":"","existingSecret":"","keys":[]}` | Private CA certificates to trust, on top of the system bundle. The adapter is a Go program, so this covers every outbound TLS call it makes: pulling image manifests from a registry with an internal CA, a TLS Redis, an HTTPS Clair endpoint.  Two mechanisms are set up together, deliberately. The bundle is mounted at `/etc/scanner-clair/extra-ca` and `SSL_CERT_DIR=/etc/ssl/certs:/etc/scanner-clair/extra-ca` is set, which covers a whole-bundle mount with `keys: []`; the system path is listed explicitly on purpose, because Go replaces its default directory list when `SSL_CERT_DIR` is set. Naming `keys` additionally emits `SCANNER_TLS_CLIENTCAS`, the adapter's own list of PEM files to append to the system pool. |
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
| lifecycle | object | `{}` | Container lifecycle hooks. |
| logLevel | string | `"info"` | Adapter log level: `trace`, `debug`, `info`, `warn`, `warning`, `error`. Anything unrecognized falls back to `info`. |
| metrics.serviceMonitor.annotations | object | `{}` | Extra annotations. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. Requires the `monitoring.coreos.com/v1` CRD. The adapter always serves `/metrics` on the API port; there is no switch to turn the endpoint itself off. |
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
| networkPolicy.egressEnabled | bool | `false` | Restrict egress as well. Leave off unless you enumerate Redis, the registry, and the Clair server in `networkPolicy.egress`. |
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
| priorityClassName | string | `""` | PriorityClass for the adapter pods. |
| probes | object | `{"liveness":{"failureThreshold":10,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"readiness":{"failureThreshold":3,"httpGet":{"path":"/probe/ready","port":"api-server"},"periodSeconds":10,"timeoutSeconds":3},"startup":{"failureThreshold":15,"httpGet":{"path":"/probe/healthy","port":"api-server"},"periodSeconds":2,"timeoutSeconds":3}}` | Container probes, passed through verbatim. The chart fills in `scheme: HTTPS` when `api.tls.enabled` is set and no scheme is given. Set a probe to `null` to drop it. Note that the adapter answers `/probe/ready` with a bare 200: it checks neither Redis nor Clair. |
| proxy.httpProxy | string | `""` | HTTP proxy URL. |
| proxy.httpsProxy | string | `""` | HTTPS proxy URL. |
| proxy.noProxy | string | `""` | Comma-separated hosts the proxy settings do not apply to. Redis, Clair and the Harbor registry normally belong here. |
| redis.existingSecret | string | `""` | Existing Secret holding the complete Redis URL. Wins over `url` and keeps the password out of the pod spec. |
| redis.existingSecretKey | string | `"url"` | Key within `redis.existingSecret`. |
| redis.pool.connectionTimeout | string | `"1s"` | Connection timeout. |
| redis.pool.idleTimeout | string | `"5m"` | Idle connection lifetime. `0` keeps idle connections open forever. |
| redis.pool.maxActive | int | `5` | Maximum connections allocated by the pool. |
| redis.pool.maxIdle | int | `5` | Maximum idle connections kept in the pool. |
| redis.pool.readTimeout | string | `"1s"` | Read timeout for a single command reply. |
| redis.pool.writeTimeout | string | `"1s"` | Write timeout for a single command. |
| redis.url | string | `"redis://harbor-harbor-redis:6379"` | Redis URL. Supports a standalone server (`redis://[:password@]host:port/db`) and Sentinel (`redis+sentinel://[:password@]host1:port1,host2:port2/monitor/db`). A password inlined here lands in the pod spec in clear text - use `existingSecret` instead. |
| replicaCount | int | `1` | Number of adapter replicas. The adapter holds no local state - the reports live in Redis and the vulnerability data in Clair - so replicas buy availability and scan throughput alike. |
| resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Resource requests and limits. The adapter transforms JSON and waits on Clair; the scanning itself, and the vulnerability database with it, live in the Clair server. Raise memory for very large manifests, not for scan volume. |
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
| store.redisNamespace | string | `"harbor.scanner.clair:store"` | Key namespace for scan jobs and reports. |
| store.redisScanJobTTL | string | `"1h"` | TTL for persisted scan jobs and reports. A report is unreadable once it expires, so keep it comfortably above the time Harbor takes to collect one. |
| strategy | object | `{}` | Deployment update strategy. Empty means the Kubernetes default (`RollingUpdate`, 25% surge and unavailable). |
| terminationGracePeriodSeconds | int | `60` | Grace period for a terminating pod. In-flight scans are lost on shutdown regardless (the worker pool does not drain), so this only bounds how long the kubelet waits before SIGKILL. |
| tls.insecureSkipVerify | bool | `false` | Skip TLS verification on every outbound connection the adapter makes - the registry and Clair both. A blunt instrument; for a private CA use `extraCA` instead. |
| tolerations | list | `[]` | Tolerations for pod assignment. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints. |
