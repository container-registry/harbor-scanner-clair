# Alongside a goharbor/harbor-helm release

Deploy the adapter into the same namespace as Harbor. It shares nothing with
Harbor's own datastores: scan jobs and reports live in the adapter's `scanner`
database on Clair's PostgreSQL, so the values file only points at the Secret
holding that DSN.

**Harbor does not ship Clair.** It was removed in Harbor 2.2
(`goharbor/harbor` commit `590212b48`, November 2020), and the goharbor chart
has had no `clair` component since. `clair.url` therefore points at a Clair 4.x
server you run yourself; see [`../external-clair/`](../external-clair/) for
reference manifests.

Clair fetches the layer blobs itself, so it needs a network route to Harbor's
registry - the adapter only hands it the URLs and Harbor's token. A Clair that
cannot reach the registry fails every scan while looking perfectly healthy.

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor \
  -f values.yaml
```

Then register the scanner in Harbor (Administration -> Interrogation Services ->
Scanners -> NEW SCANNER) with the endpoint the chart prints on install:

```
http://harbor-scanner-clair.harbor.svc:8080
```

## What you need first

- A Clair 4.9+ server reachable from this namespace, which can itself reach
  Harbor's registry.
- A Secret named `harbor-scanner-clair-postgres` in this namespace, holding the
  connection string for the adapter's own database on Clair's PostgreSQL; see
  [`../external-clair/`](../external-clair/) for the database and the one-liner
  that creates the Secret.

## Do not make this the system default scanner

The adapter implements Harbor's adapter API v1.0: vulnerability reports only,
no SBOM. Harbor's Security Hub derives every registry-wide number from the
capabilities of the **system default** scanner, so promoting this adapter to
default would zero those numbers registry-wide. Register it, use it per project,
and leave the default where it is.
