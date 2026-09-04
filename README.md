[![GitHub release][release-img]][release]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Clair

The Harbor Scanner Adapter for [Clair][clair-url] is a service that translates the Harbor scanning API into Clair API calls
and allows Harbor to use Clair for providing vulnerability reports on images stored in Harbor registry as part of its
vulnerability scan feature.

> See [Proposal: Pluggable Image Vulnerability Scanning][image-vulnerability-scanning-proposal] for more details.

## TOC

* [This fork](#this-fork)
* [Configuration](#configuration)
* [Deploy to Kubernetes](#deploy-to-kubernetes)
* [Contributing](#contributing)

## This fork

Maintained by [container-registry.com], forked from [goharbor/harbor-scanner-clair], which has
had no commits since August 2020.

What this fork changed:

* Module path `github.com/container-registry/harbor-scanner-clair`, built with the Go version
  declared in [`go.mod`](go.mod).
* A Task-based build with tool and base-image pins in [`versions.env`](versions.env), in place
  of the Makefile, Travis CI and a GoReleaser config current GoReleaser refuses to read.
* Multi-arch images (`linux/amd64`, `linux/arm64`) published to
  `8gears.container-registry.com/8gcr/harbor-scanner-clair`, signed keylessly with cosign and
  carrying an SBOM attestation. Upstream published amd64-only images to Docker Hub and stopped
  at `1.1.1` in August 2020.
* An Alpine-based image that runs as a non-root user and has a health probe, in place of the
  four-line `FROM scratch` image that ran as root.
* Releases automated with release-please.

What this fork did not change. The adapter code is untouched, so these are properties of the
adapter itself and not gaps in the port:

* It speaks the **Clair v1 API** against CoreOS Clair 2.x, which is end of life. Clair 4.x is
  not supported.
* **Harbor has not bundled Clair since 2.2** (`goharbor/harbor` commit `590212b48`, November
  2020). Current Harbor neither deploys nor configures Clair, so you operate the Clair server
  yourself and register this adapter with Harbor by URL.
* It implements **Harbor scanner adapter API v1.0** only: vulnerability reports, no SBOM, no
  capability negotiation. Harbor derives its registry-wide Security Hub numbers from the
  capabilities of the system-default scanner, so this adapter should not be made the default.
* Scan jobs run on an in-process goroutine pool with no concurrency limit and no retries.
  Redis holds results, not a queue, so a restart loses every in-flight scan and leaves its
  record `Running` until the TTL expires.
* The scanner metadata Harbor displays is hardcoded to Clair / CoreOS / 2.x. It is not read
  from the backend.

Known defects that were deliberately left in place are listed under "Known rough edges" in
[`CLAUDE.md`](CLAUDE.md).

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL`                | `info` | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`          | `:8080` | Binding address for the API HTTP server. |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | | The absolute path to the x509 certificate file. |
| `SCANNER_API_SERVER_TLS_KEY`         | | The absolute path to the x509 private key file. |
| `SCANNER_TLS_INSECURE_SKIP_VERIFY` | `false` | Controls whether an HTTP client verifies the server's certificate chain and host name. |
| `SCANNER_TLS_CLIENTCAS` | | An array of absolute paths to x509 CA files that will be added to host's root CA set. |
| `SCANNER_API_SERVER_READ_TIMEOUT`  | `15s` | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s` | The maximum duration before timing out writes of the response. |
| `SCANNER_API_SERVER_IDLE_TIMEOUT`  | `60s` | The maximum amount of time to wait for the next request when keep-alives are enabled. |
| `SCANNER_CLAIR_URL`                | `http://harbor-harbor-clair:6060` | Clair URL |
| `SCANNER_CLAIR_DATABASE_URL`       | | The Clair database URL, it is used to fetch vulnerability database updated time of the Clair. Its format is `postgresql://user:password@host/db?sslmode=disable` |
| `SCANNER_STORE_REDIS_URL`                     | `redis://harbor-harbor-redis:6379` | Redis server URI for a Redis store. The URI supports schemas to connect to a standalone Redis server, i.e. `redis://user:password@standalone_host:port/db-number` and Redis Sentinel deployment, i.e. `redis+sentinel://user:password@sentinel_host1:port1,sentinel_host2:port2/monitor-name/db-number`. |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE`         | `5`   | The max number of connections allocated by the pool for a Redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`           | `5`   | The max number of idle connections in the pool for a Redis store. |
| `SCANNER_STORE_REDIS_POOL_IDLE_TIMEOUT`       | `5m`  | Close connections after remaining idle for this duration. |
| `SCANNER_STORE_REDIS_POOL_CONNECTION_TIMEOUT` | `1s`  | The timeout for connecting to the Redis server. |
| `SCANNER_STORE_REDIS_POOL_READ_TIMEOUT`       | `1s`  | The timeout for reading a single Redis command reply. |
| `SCANNER_STORE_REDIS_POOL_WRITE_TIMEOUT`      | `1s`  | The timeout for writing a single Redis command. |
| `SCANNER_STORE_REDIS_NAMESPACE`       | `harbor.scanner.clair:store` | A namespace for keys in a redis store. |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`    | `1h`                         | The time to live for persisting scan jobs and associated scan reports. |

## Deploy to Kubernetes

[`kube/harbor-scanner-clair.yaml`](kube/harbor-scanner-clair.yaml) runs the published image
`8gears.container-registry.com/8gcr/harbor-scanner-clair:latest` as a single-replica
`Deployment` behind a `LoadBalancer` `Service` on port 8443, serving HTTPS. Its inlined env
block points `SCANNER_CLAIR_URL` and `SCANNER_STORE_REDIS_URL` at in-cluster defaults; edit
them for your Clair and Redis before applying. There is no Helm chart yet.

1. Configure the adapter to handle TLS traffic:
   1. Generate certificate and private key files:
      ```
      $ openssl genrsa -out tls.key 2048
      $ openssl req -new -x509 \
        -key tls.key \
        -out tls.crt \
        -days 365 \
        -subj /CN=harbor-scanner-clair
      ```
   2. Create a `tls` secret from the two generated files:
      ```
      $ kubectl create secret tls harbor-scanner-clair-tls \
        --cert=tls.crt \
        --key=tls.key
      ```
2. Create the `harbor-scanner-clair` deployment and service:
   ```
   kubectl apply -f kube/harbor-scanner-clair.yaml
   ```
3. If everything is fine you should be able to get the scanner's metadata:
   ```
   kubectl port-forward service/harbor-scanner-clair 8443:8443 &> /dev/null &
   curl -vk https://localhost:8443/api/v1/metadata | jq
   ```
4. Register the adapter in Harbor under Administration > Interrogation Services > Scanners,
   using the URL at which Harbor can reach the service, and tick **Skip certificate
   verification**: the certificate generated above is self-signed and carries no SAN. Harbor's
   **Test Connection** button calls the same `/api/v1/metadata` endpoint.

To try a locally built image instead of the published one, build it into the cluster's Docker
daemon and change the `image:` field in the manifest:

```
eval $(minikube docker-env -p harbor)
task image:local
```

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the build and test commands,
and the commit conventions releases depend on.

[release-img]: https://img.shields.io/github/release/container-registry/harbor-scanner-clair.svg
[release]: https://github.com/container-registry/harbor-scanner-clair/releases
[report-card-img]: https://goreportcard.com/badge/github.com/container-registry/harbor-scanner-clair
[report-card]: https://goreportcard.com/report/github.com/container-registry/harbor-scanner-clair
[license-img]: https://img.shields.io/github/license/container-registry/harbor-scanner-clair.svg
[license]: https://github.com/container-registry/harbor-scanner-clair/blob/main/LICENSE

[container-registry.com]: https://container-registry.com
[goharbor/harbor-scanner-clair]: https://github.com/goharbor/harbor-scanner-clair

[clair-url]: https://github.com/coreos/clair
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
