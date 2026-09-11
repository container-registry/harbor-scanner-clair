# Moving from `kube/harbor-scanner-clair.yaml`, and from adapter 1.x

The repository shipped a pair of raw manifests at `kube/harbor-scanner-clair.yaml`:
one Service and one Deployment, with the adapter's environment written out
inline. They were **removed in adapter 2.0.0**; the last tree that has them is
commit
[`b9f89a8`](https://github.com/container-registry/harbor-scanner-clair/blob/b9f89a8/kube/harbor-scanner-clair.yaml),
so the mapping below stays checkable.

This document does two jobs: it maps those manifests onto chart values, and it
lists what changed in the adapter's environment between 1.x and 2.0.0.

There is no upgrade path to run from the manifests: the objects have different
names and different owners, so install the chart and delete the old manifests.

## Environment variables

The manifest set twelve. Nine map onto a value, one has no successor at all, and
two are set by the chart itself when TLS is on.

| Manifest environment variable | Chart value |
|---|---|
| `SCANNER_LOG_LEVEL` | `logLevel` |
| `SCANNER_API_SERVER_ADDR` | `service.port` - the chart renders `:{{ port }}` |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | not a value. Set to `/certs/tls.crt` by the chart when `api.tls.enabled` |
| `SCANNER_API_SERVER_TLS_KEY` | not a value. Set to `/certs/tls.key` by the chart when `api.tls.enabled` |
| `SCANNER_API_SERVER_READ_TIMEOUT` | `api.readTimeout` |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `api.writeTimeout` |
| `SCANNER_CLAIR_URL` | `clair.url` |
| `SCANNER_STORE_REDIS_URL` | the store is PostgreSQL in 2.0.0: `postgres.url`, or `postgres.existingSecret`. Either way the chart emits a `secretKeyRef`, never a literal |
| `SCANNER_STORE_REDIS_NAMESPACE` | no successor. One table, one row per job, so there is no key namespace to set |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL` | `store.scanJobTTL`, which the chart emits as `SCANNER_STORE_SCAN_JOB_TTL` |
| `SCANNER_TLS_INSECURE_SKIP_VERIFY` | `tls.insecureSkipVerify` |
| `SCANNER_TLS_CLIENTCAS` | `extraCA.existingSecret` plus `extraCA.keys`; the chart joins the mounted paths |

The variables the manifest did not set, and where they come from:

| Environment variable | Chart value |
|---|---|
| `SCANNER_API_SERVER_IDLE_TIMEOUT` | `api.idleTimeout` |
| `SCANNER_API_SERVER_METRICS_ENABLED` | `metrics.enabled` |
| `SCANNER_API_AUTH_API_KEY` | no dedicated value: it is a credential, so set `secret.scanner.api.auth.api_key` |
| `SCANNER_CLAIR_PSK` | `clair.psk`, or `clair.existingSecret` plus `clair.existingSecretKey` |
| `SCANNER_CLAIR_JWT_ISSUER` | `clair.jwtIssuer` |
| `SCANNER_CLAIR_INDEX_TIMEOUT` | `clair.indexTimeout` |
| `SCANNER_CLAIR_REQUEST_TIMEOUT` | `clair.requestTimeout` |
| `SCANNER_STORE_BACKEND` | `store.backend` |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` | `jobQueue.workerConcurrency` |
| `SCANNER_STORE_POSTGRES_MAX_CONNS` | no dedicated value; the adapter's default of 5 per replica is usually right, and `config.scanner.store.postgres.max_conns` reaches it |

The chart emits all of them except `SCANNER_STORE_POSTGRES_MAX_CONNS`, with the
adapter's own defaults as the chart defaults, so nothing changes behaviour by
appearing.

## 1.x to 2.0.0 environment changes

**Removed:** `SCANNER_CLAIR_DATABASE_URL`. The adapter no longer connects to
Clair's PostgreSQL: Clair 4.x exposes updater state over HTTP, so the
vulnerability-database timestamp comes from the matcher API. The chart values
`clair.databaseUrl` is gone with it, and `clair.existingSecret` now holds the
pre-shared key rather than a DSN.

**Removed:** every `SCANNER_STORE_REDIS_*` variable and
`SCANNER_JOB_QUEUE_REDIS_NAMESPACE`. The job store and the queue are one
PostgreSQL table now, so `SCANNER_STORE_REDIS_URL`, the six pool variables and
the key namespace have no successor; `SCANNER_STORE_REDIS_SCAN_JOB_TTL` is
renamed to `SCANNER_STORE_SCAN_JOB_TTL`, and the chart values `redis.*` and
`store.redisNamespace` are gone with them. 1.x installs need a `scanner`
database and a DSN before they upgrade; nothing migrates, and in-flight scan
jobs are lost, which costs a rescan.

**Added:** `SCANNER_STORE_POSTGRES_URL` and `SCANNER_STORE_POSTGRES_MAX_CONNS`,
plus the other variables in the second table above, except
`SCANNER_API_SERVER_IDLE_TIMEOUT`, which 1.x already read. Of the new ones,
`SCANNER_STORE_POSTGRES_URL` is required, and `SCANNER_CLAIR_PSK` and
`SCANNER_CLAIR_JWT_ISSUER` usually need attention: a Clair with an `auth` stanza
answers 401 to an adapter with no key, and rejects a token whose `iss` claim is
not in its `auth.psk.iss` list.

## Three deliberate differences

**`LoadBalancer` becomes `ClusterIP`.** The manifest exposed the adapter outside
the cluster. Harbor calls it from inside, so the chart defaults to `ClusterIP`.
Set `service.type: LoadBalancer` to get the old shape back.

**Port 8443 with TLS becomes port 8080 without.** The manifest hardcoded an
HTTPS listener on 8443 and expected a Secret named `harbor-scanner-clair-tls` to
exist. The chart defaults to plaintext on 8080, which is what an in-cluster
Harbor usually wants, and makes TLS a switch:

```yaml
service:
  port: 8443
api:
  tls:
    enabled: true
    existingSecret: harbor-scanner-clair-tls
```

The chart then mounts the Secret at `/certs`, sets both TLS variables, and flips
the probes to `scheme: HTTPS`.

**Root becomes UID 10000.** The manifest set no security context, so the pod ran
as whatever the image's user is. The chart runs the adapter as UID/GID 10000
with a read-only root filesystem, no privilege escalation and all capabilities
dropped. On OpenShift, see [`../example/openshift/`](../example/openshift/).

## Equivalent install

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor \
  --set clair.url=http://clair.clair.svc:6060 \
  --set postgres.existingSecret=harbor-scanner-clair-postgres \
  --set store.scanJobTTL=1h
```

`store.scanJobTTL` is already the chart default. In practice the install is
`--set clair.url=<your Clair>`, a Secret holding the connection string for the
adapter's own database, and a pre-shared key if your Clair authenticates.
