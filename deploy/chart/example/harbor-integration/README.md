# Alongside a goharbor/harbor-helm release

Deploy the adapter into the same namespace as Harbor and point it at Harbor's
own Redis. The values file overrides the Redis host and picks a dedicated
database number so the adapter's keys do not share space with Harbor's.

**Harbor does not ship Clair.** It was removed in Harbor 2.2
(`goharbor/harbor` commit `590212b48`, November 2020), and the goharbor chart
has had no `clair` component since. `clair.url` therefore points at a Clair 2.x
server you run yourself; there is no `harbor-harbor-clair` Service to fall back
on in a current Harbor install, despite it still being the adapter's compiled-in
default. See [`../external-clair/`](../external-clair/) for reference manifests.

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

- A Clair 2.x server reachable from this namespace.
- A Harbor release whose Redis Service is `harbor-redis`. Confirm the name -
  the goharbor chart calls it `<release>-redis`, so a release named `harbor`
  gives `harbor-redis`, and the older `<release>-harbor-redis` naming is still
  out there. `kubectl -n harbor get svc | grep redis` settles it.
- Redis database `5` free for the adapter. Harbor itself uses `0`-`4`.

## Do not make this the system default scanner

The adapter implements Harbor's adapter API v1.0: vulnerability reports only,
no SBOM. Harbor's Security Hub derives every registry-wide number from the
capabilities of the **system default** scanner, so promoting this adapter to
default would zero those numbers registry-wide. Register it, use it per project,
and leave the default where it is.
