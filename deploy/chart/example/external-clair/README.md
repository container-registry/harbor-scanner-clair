# Standing up a Clair 4.x backend

This chart deploys the **adapter**, not Clair. Harbor removed its bundled Clair
in 2.2 (`goharbor/harbor` commit `590212b48`, November 2020), so the backend is
yours to operate, and `clair.url` is the one setting the adapter cannot do
without.

Clair 4.x is a second workload with its own PostgreSQL, its own configuration
file and its own vulnerability-feed lifecycle. The adapter needs that same
PostgreSQL server: it keeps one row per scan job in a `scan_job` table, in a
database of its own (`scanner`) that `postgres.yaml` creates alongside Clair's. That is a chart of its own rather
than a subchart of a scanner adapter, so what follows is raw reference
manifests: Clair 4.9.0 in combo mode (indexer, matcher and notifier in one
process) against PostgreSQL 15.

> **Evaluation-grade.** A single Clair replica, a single-instance database and
> passwords in manifests. Enough to evaluate the adapter and a starting point
> for a real deployment, not a substitute for one.

## Generate the pre-shared key once, use it in both places

Clair authenticates every API call with an HS256 JWT signed with a shared key,
and the adapter signs one per call. Both sides take the key **base64-encoded**;
Clair decodes it at startup, so a placeholder that is not valid base64 fails
`check-config` and aborts the process.

```sh
PSK=$(openssl rand -base64 32)

# 1. into clair.yaml, replacing REPLACE_ME_BASE64 in auth.psk.key
# 2. as the Secret the adapter reads, in the adapter's namespace
kubectl -n harbor create secret generic clair-psk --from-literal=psk="$PSK"
```

## Give the adapter its database

`postgres.yaml` creates the `scanner` database next to Clair's own. Hand the
adapter a DSN for it, in the adapter's namespace - the same `REPLACE_ME`
password as everywhere else:

```sh
kubectl -n harbor create secret generic harbor-scanner-clair-postgres \
  --from-literal=url='postgres://clair:REPLACE_ME@clair-postgres.clair.svc:5432/scanner?sslmode=disable'
```

Postgres runs in the `clair` namespace and the adapter in `harbor`, so the host
has to be the cross-namespace name `clair-postgres.clair.svc`; the chart default
is the short form, which only resolves for an adapter installed next to it. The
`clair` role owns both databases, which is what lets the adapter run its
`CREATE TABLE IF NOT EXISTS scan_job` at startup.

Replace `REPLACE_ME` in **both** manifests too: the database password appears in
`clair.yaml`'s three connection strings and in `postgres.yaml`'s Secret, and
they have to match. The adapter's DSN below carries the same password again.

The configuration is a Secret rather than a ConfigMap because Clair has no
environment override for any config key (only `CLAIR_MODE` and `CLAIR_CONF`), so
one file carries both the database password and the key. If you externalise the
database password some other way, a ConfigMap works identically.

## Apply

```sh
kubectl apply -f postgres.yaml
kubectl apply -f clair.yaml
kubectl -n clair rollout status deploy/clair
```

Validate the config before you apply an edited copy. `check-config` takes the
bare Clair config, not the Kubernetes manifest, so extract the `config.yaml` key
from the Secret first. Unknown keys abort startup rather than warning, and
`check-config` exits non-zero on them:

```sh
yq 'select(.kind == "Secret") | .stringData["config.yaml"]' clair.yaml > config.yaml
docker run --rm -v "$PWD:/config:ro" --entrypoint /usr/bin/clairctl \
  quay.io/projectquay/clair:4.9.0 check-config /config/config.yaml
```

## What to expect on first start

Clair runs its own migrations, then starts an updater cycle. Until that cycle
has put something in the vulnerability table, the matcher answers **202** with
an empty body, the adapter stays unready, and every scan sits pending.

Measured on a laptop against 4.9.0 with the set trimmed to
`[alpine, clair.cvss]`: the matcher stopped answering 202 after 16 seconds and
the first full cycle finished at 85 seconds. The four sets configured here
(`alpine`, `debian`, `ubuntu`, `clair.cvss`) download more and take
correspondingly longer. The CVSS enricher walks the NVD JSON feeds year by year
from 2002 and is the whole memory peak: 1805 MiB measured, dropping to 228 MiB
once it finished.

```sh
kubectl -n clair logs deploy/clair -f
```

The readiness probe uses Clair's introspection port, `:8089/readyz`, which sits
outside the PSK authentication middleware. That is why the probes need no token
while the API on 6060 stays protected. A ready pod means the vulnerability table
is non-empty, not that the update cycle finished and not that CVSS enrichment is
loaded, so reports can arrive without scores for a little longer.

## Clair pulls the layers

The adapter hands Clair a per-layer URL and the `Authorization` header from
Harbor's scan request; **Clair** does the GET. So Clair, not just the adapter,
needs a route to Harbor's registry, and any NetworkPolicy in the `clair`
namespace has to allow it. Clair also needs to trust that registry's CA, which
is Clair's own trust store, not the adapter's `extraCA`.

Clair decompresses layers into `TMPDIR` while indexing; the `emptyDir` mounted
at `/var/tmp` is that scratch space, and the rule of thumb is roughly twice the
largest uncompressed layer you expect to scan.

## Install the adapter against it

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

## Air-gapped installs

`indexer.airgap: true` blocks egress to public addresses while still permitting
RFC 1918 and RFC 4193, so an in-cluster registry keeps working. Pair it with
`matcher.disable_updaters: true` and load the vulnerability data with
`clairctl export-updaters` on a connected host and `clairctl import-updaters`
here.
