# OpenShift

The chart's defaults pin `runAsUser`, `runAsGroup` and `fsGroup` to `10000`.
OpenShift's `restricted-v2` SCC allocates a UID range per namespace and rejects
a pod that asks for a UID outside it, so those defaults have to come off and let
OpenShift assign.

The trap is that Helm **deep-merges** maps from `-f`, so writing a
`podSecurityContext` without those keys does not remove them - the chart's
values survive underneath. They have to be set to `null` explicitly, which is
what the values file here does. Check your work:

```sh
helm template harbor-scanner-clair . -f values.yaml \
  | grep -A6 'securityContext:'
```

You should see `runAsNonRoot` and `seccompProfile` and nothing else.

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

## Why the image still works unowned

The adapter writes only to `/tmp`, which the chart mounts as an `emptyDir`.
OpenShift runs the container with an arbitrary UID in the root group (GID 0),
and the base image's `/home/scanner` tree is group-readable, so the binary
starts. There is no persistent volume in this chart, which removes the usual
`fsGroup` ownership problem entirely - the adapter keeps nothing on disk, the
reports live in Redis and the vulnerability data in Clair.
