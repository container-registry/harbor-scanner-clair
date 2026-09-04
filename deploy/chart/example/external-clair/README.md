# Standing up a Clair backend

This chart deploys the **adapter**, not Clair. Harbor removed its bundled Clair
in 2.2 (`goharbor/harbor` commit `590212b48`, November 2020), so the backend is
yours to operate, and `clair.url` is the one setting the adapter cannot do
without.

Clair 2.x is a second workload with its own PostgreSQL, its own configuration
file and its own vulnerability-feed lifecycle. That is a chart of its own rather
than a subchart of a scanner adapter, so what follows is raw reference
manifests.

> **Evaluation-grade and unsupported.** CoreOS Clair 2.x is end of life. These
> manifests run a single replica against an `emptyDir` PostgreSQL with a
> password in a ConfigMap. Do not run them in production; run your own Clair,
> and point `clair.url` at it.

## Apply

```sh
kubectl apply -f clair.yaml
kubectl apply -f postgres.yaml
kubectl -n clair rollout status deploy/clair
```

Replace `REPLACE_ME` in **both** files first - the DSN in `clair.yaml`'s
ConfigMap and the password in `postgres.yaml`'s Secret have to match.

Clair runs its database migrations on first start and then fetches the
vulnerability feeds, which takes several minutes. Until that finishes it answers
the API but reports nothing.

```sh
kubectl -n clair logs deploy/clair | grep 'finished fetching'
```

Some upstream feeds (Oracle Linux, Amazon Linux) now answer 403 or 429 to
Clair 2.x. Those updaters log `could not download requested resource` and are
skipped; the rest still load.

## Install the adapter against it

The DSN is optional. It is read for exactly one query, `updater/last`, which
becomes the vulnerability-database timestamp in `/api/v1/metadata`.

```sh
kubectl -n harbor create secret generic clair-database-dsn \
  --from-literal=databaseUrl='postgres://clair:REPLACE_ME@clair-postgres.clair.svc:5432/clair?sslmode=disable'

helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

## Which Clair images are still pullable

| Image | State |
|-------|-------|
| `goharbor/clair-photon:v1.10.19` | Harbor's own Clair 2.x build. Anonymously pullable, last pushed 2024-09-20. Used here |
| `arminc/clair-local-scan:latest` | Clair 2.1.8. Convenient for a throwaway smoke test, but it hardcodes a PostgreSQL at the host `postgres` and exits if it is absent; pair it with `arminc/clair-db`, which ships a preloaded vulnerability database |
| `quay.io/coreos/clair` | **Not** anonymously pullable; returns 401 even with an anonymous pull token |

## What the adapter actually needs

One HTTP endpoint speaking the Clair **v1** API: `POST /v1/layers` and
`GET /v1/layers/{name}?features&vulnerabilities`. The Clair 4.x indexer/matcher
split is a different API and is not supported.
