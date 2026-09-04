# Moving from `kube/harbor-scanner-clair.yaml`

The repository ships a pair of raw manifests at
[`kube/harbor-scanner-clair.yaml`](../../../kube/harbor-scanner-clair.yaml): one
Service and one Deployment, with the adapter's environment written out inline.
They predate this chart and stay as a minimal reference. This maps them onto
chart values.

There is no upgrade path to run: the objects have different names and different
owners, so install the chart and delete the old manifests.

## Environment variables

The manifest sets twelve. Ten map onto a value; two are set by the chart itself
when TLS is on.

| Manifest environment variable | Chart value |
|---|---|
| `SCANNER_LOG_LEVEL` | `logLevel` |
| `SCANNER_API_SERVER_ADDR` | `service.port` - the chart renders `:{{ port }}` |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | not a value. Set to `/certs/tls.crt` by the chart when `api.tls.enabled` |
| `SCANNER_API_SERVER_TLS_KEY` | not a value. Set to `/certs/tls.key` by the chart when `api.tls.enabled` |
| `SCANNER_API_SERVER_READ_TIMEOUT` | `api.readTimeout` |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `api.writeTimeout` |
| `SCANNER_CLAIR_URL` | `clair.url` |
| `SCANNER_STORE_REDIS_URL` | `redis.url`, or `redis.existingSecret` to keep the password out of the pod spec |
| `SCANNER_STORE_REDIS_NAMESPACE` | `store.redisNamespace` |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL` | `store.redisScanJobTTL` |
| `SCANNER_TLS_INSECURE_SKIP_VERIFY` | `tls.insecureSkipVerify` |
| `SCANNER_TLS_CLIENTCAS` | `extraCA.existingSecret` plus `extraCA.keys`; the chart joins the mounted paths |

The manifest does not set `SCANNER_API_SERVER_IDLE_TIMEOUT`,
`SCANNER_CLAIR_DATABASE_URL` or the six `SCANNER_STORE_REDIS_POOL_*` variables.
The chart emits all of them from `api.idleTimeout`, `clair.databaseUrl` (or
`clair.existingSecret`) and `redis.pool.*`, with the adapter's own defaults as
the chart defaults, so nothing changes behaviour by appearing.

## Three deliberate differences

**`LoadBalancer` becomes `ClusterIP`.** The manifest exposes the adapter outside
the cluster. Harbor calls it from inside, so the chart defaults to `ClusterIP`.
Set `service.type: LoadBalancer` to get the old shape back.

**Port 8443 with TLS becomes port 8080 without.** The manifest hardcodes an
HTTPS listener on 8443 and expects a Secret named `harbor-scanner-clair-tls` to
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

**Root becomes UID 10000.** The manifest sets no security context, so the pod
runs as whatever the image's user is. The chart runs the adapter as UID/GID
10000 with a read-only root filesystem, no privilege escalation and all
capabilities dropped. On OpenShift, see
[`../example/openshift/`](../example/openshift/).

## Equivalent install

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor \
  --set clair.url=http://harbor-harbor-clair:6060 \
  --set redis.url=redis://harbor-harbor-redis:6379 \
  --set store.redisNamespace=harbor.scanner.clair:store \
  --set store.redisScanJobTTL=1h
```

Every one of those is already the chart default, so in practice the install is
`--set clair.url=<your Clair>` and nothing else.
