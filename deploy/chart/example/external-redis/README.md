# Password-protected external Redis

The adapter takes its Redis connection as a single URL, so the password is part
of it. Setting `redis.url` inline puts that password in the Deployment's pod
spec, readable by anyone with `get pods` in the namespace.
`redis.existingSecret` reads the whole URL from a Secret instead, and the value
only ever appears in the container's environment.

Create the Secret yourself:

```sh
kubectl -n harbor create secret generic harbor-scanner-clair-redis \
  --from-literal=url='redis://:s3cr3t@redis.example.com:6379/5'
```

Sentinel works the same way:

```
redis+sentinel://:s3cr3t@sentinel-a:26379,sentinel-b:26379/mymaster/5
```

Then:

```sh
helm install harbor-scanner-clair \
  oci://8gears.container-registry.com/8gcr/charts/harbor-scanner-clair \
  --namespace harbor -f values.yaml
```

Redis here is a result store, not a queue: one JSON document per scan job,
expiring after `store.redisScanJobTTL`. Losing it loses in-flight reports, not
the ability to scan again.
