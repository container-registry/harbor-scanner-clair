# HTTPS API with a cert-manager certificate

cert-manager writes a `kubernetes.io/tls` Secret; `api.tls.existingSecret`
consumes it directly, so no certificate material is ever stored in values or in
Git. The Certificate itself rides along in `extraManifests`, which means one
`helm install` produces both.

The SAN must be the in-cluster Service DNS name Harbor will connect to, or
Harbor rejects the scanner with a certificate error.

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

Register the scanner with the `https://` endpoint. Harbor must trust the issuing
CA - either add it to Harbor's trust store, or tick "Skip certificate
verification" on the scanner registration (test clusters only).

## This is server TLS only

There is no mutual-TLS option. The adapter's API server never sets `ClientCAs`
or `ClientAuth` (`pkg/http/api/server.go`), so it cannot require a client
certificate from Harbor no matter what is mounted. Restricting *who* may call
the adapter is a `networkPolicy.ingress` job here, not a TLS one.

`SCANNER_TLS_CLIENTCAS`, despite the name, is the opposite direction: it is the
adapter's own outbound trust list. See [`../private-ca/`](../private-ca/).

## What you need first

- cert-manager installed, with an Issuer or ClusterIssuer named below.
