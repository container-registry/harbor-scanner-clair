# Registry, PostgreSQL or Clair behind a private CA

The adapter pulls image manifests over TLS, talks to Clair over HTTP or HTTPS,
and reaches its own database with whatever `sslmode` the DSN asks for. It is a
Go program throughout. `extraCA` mounts your PEM bundle and
makes the adapter trust it, which covers every outbound TLS call it makes.

```sh
kubectl -n harbor create secret generic corp-ca --from-file=ca.crt=./corp-ca.pem

helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

## Two mechanisms, and why both are set

**`SCANNER_TLS_CLIENTCAS`** is the adapter's own list of PEM *files*. At startup
it reads each one and appends it to the pool returned by
`x509.SystemCertPool()` (`pkg/etc/config.go`). The chart emits it only when
`extraCA.keys` names files, because it cannot enumerate the keys of a Secret it
does not own. The name is misleading: these are not client CAs for verifying
callers, they are root CAs for outbound connections.

**`SSL_CERT_DIR`** is Go's own knob, and it is what covers a whole-bundle mount
with `keys: []`. The chart sets it to
`/etc/ssl/certs:/etc/scanner-clair/extra-ca`.

Go's `crypto/x509` **replaces** its default directory list when `SSL_CERT_DIR`
is set rather than adding to it. Pointing it at the mount alone would drop the
system roots, and the first thing to break would be a public HTTPS call -
which looks like a network fault, not a trust one. Listing `/etc/ssl/certs`
explicitly keeps the public bundle. Order does not matter; a certificate in
either directory is trusted.

## Verifying

```sh
kubectl -n harbor exec deploy/harbor-scanner-clair -- \
  ls /etc/scanner-clair/extra-ca
kubectl -n harbor logs deploy/harbor-scanner-clair | grep -i "certificate\|x509"
```

Clair needs the same CA in its own trust store if the registry is behind one:
Clair pulls the layer blobs itself, and `extraCA` reaches only the adapter.

An `x509: certificate signed by unknown authority` in the logs means the bundle
is missing the issuer, not that the mount failed. A startup failure naming
`failed to append ... to root CAs pool` means `extraCA.keys` names a file that
is absent from the Secret, or that is not PEM.
