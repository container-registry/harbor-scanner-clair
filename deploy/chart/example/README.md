# Examples

Each directory is a self-contained scenario: a `values.yaml` you can pass to
`helm install -f`, plus a README explaining what it is for and what you have to
create yourself. CI renders every `values*.yaml` under this tree on each chart
change, so none of them can silently rot.

| Example | What it shows |
|---------|---------------|
| [`external-clair/`](external-clair/) | Standing up a Clair 4.x backend to point the adapter at. Start here: the chart does not ship one |
| [`harbor-integration/`](harbor-integration/) | Adapter alongside a `goharbor/harbor-helm` release, pointed at a Clair you operate |
| [`tls-cert-manager/`](tls-cert-manager/) | HTTPS API with a cert-manager-issued certificate |
| [`flux/`](flux/) | GitOps delivery with FluxCD: digest-pinned image, externally owned Secrets |
| [`openshift/`](openshift/) | Letting OpenShift's SCC assign the UID/GID range instead of pinning one |
| [`private-ca/`](private-ca/) | Trusting a private CA for outbound connections to the registry, PostgreSQL and Clair |
