{{/* vim: set filetype=mustache: */}}

{{/*
Chart name, optionally overridden.
*/}}
{{- define "harbor-scanner-clair.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified resource name. Truncated at 63 characters for the DNS label
limit; the ReplicaSet appends a pod-template hash and an ordinal to it for pod
names, so the practical budget is a little lower.
*/}}
{{- define "harbor-scanner-clair.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-clair.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels. These land in an immutable Deployment selector, so they must
never gain a value that changes between upgrades (the chart version, in
particular).
*/}}
{{- define "harbor-scanner-clair.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-clair.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "harbor-scanner-clair.labels" -}}
helm.sh/chart: {{ include "harbor-scanner-clair.chart" . }}
{{ include "harbor-scanner-clair.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: scanner-adapter
app.kubernetes.io/part-of: harbor
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Annotations for a rendered object: chart-wide commonAnnotations merged with the
object's own. Emits nothing when both are empty, so callers can guard with
`with` and avoid an empty `annotations:` key.
*/}}
{{- define "harbor-scanner-clair.annotations" -}}
{{- $annotations := merge (deepCopy (.local | default dict)) (.root.Values.commonAnnotations | default dict) -}}
{{- with $annotations }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{/*
Image reference. global.imageRegistry wins over image.registry and preserves
the repository path; image.digest wins over image.tag.
*/}}
{{- define "harbor-scanner-clair.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $ref := .Values.image.repository -}}
{{- if $registry -}}
{{- $ref = printf "%s/%s" $registry .Values.image.repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $ref .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $ref (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Merged pull secrets. Emits nothing when there are none, so the caller must
guard with `with` to avoid an empty line in the pod spec.
*/}}
{{- define "harbor-scanner-clair.imagePullSecrets" -}}
{{- $names := list -}}
{{- if .Values.imageCredentials.create -}}
{{- $names = append $names (printf "%s-registry" (include "harbor-scanner-clair.fullname" .)) -}}
{{- end -}}
{{- /* Both spellings are in the wild - a bare name and a LocalObjectReference -
      and they must be reduced to names before uniq, or "a" and {name: a}
      survive as two distinct entries. */ -}}
{{- range concat (.Values.global.imagePullSecrets | default list) (.Values.image.pullSecrets | default list) -}}
{{- if kindIs "string" . -}}
{{- $names = append $names . -}}
{{- else -}}
{{- $names = append $names (.name | default "") -}}
{{- end -}}
{{- end -}}
{{- range (compact $names | uniq) }}
- name: {{ . }}
{{- end }}
{{- end -}}

{{- define "harbor-scanner-clair.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "harbor-scanner-clair.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
TLS. Non-empty output means the API serves HTTPS.
*/}}
{{- define "harbor-scanner-clair.tls.enabled" -}}
{{- if .Values.api.tls.enabled -}}enabled{{- end -}}
{{- end -}}

{{- define "harbor-scanner-clair.tls.secretName" -}}
{{- .Values.api.tls.existingSecret | default (printf "%s-tls" (include "harbor-scanner-clair.fullname" .)) -}}
{{- end -}}

{{/*
Clair pre-shared key source. Non-empty output is the Secret name holding the
base64 PSK; empty means no PSK is configured and the adapter sends no
Authorization header.
*/}}
{{- define "harbor-scanner-clair.clair.pskSecretName" -}}
{{- if .Values.clair.existingSecret -}}
{{- .Values.clair.existingSecret -}}
{{- else if .Values.clair.psk -}}
{{- include "harbor-scanner-clair.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-clair.clair.pskSecretKey" -}}
{{- if .Values.clair.existingSecret -}}
{{- .Values.clair.existingSecretKey -}}
{{- else -}}
psk
{{- end -}}
{{- end -}}

{{/*
Job store DSN source. Non-empty output is the Secret name holding the complete
connection string; empty means the memory backend, which needs no database.

The DSN is never inlined into the pod spec, unlike the Clair URL next to it: a
connection string carries the password in its userinfo, so a DSN set in values
goes through the chart-managed Secret instead.
*/}}
{{- define "harbor-scanner-clair.postgres.secretName" -}}
{{- if eq .Values.store.backend "postgres" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else if .Values.postgres.url -}}
{{- include "harbor-scanner-clair.fullname" . -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-clair.postgres.secretKey" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecretKey -}}
{{- else -}}
url
{{- end -}}
{{- end -}}

{{/*
Render one probe verbatim, injecting scheme: HTTPS when the API serves TLS and
the caller did not pick a scheme. Usage:
  {{- include "harbor-scanner-clair.probe" (dict "root" $ "probe" .Values.probes.liveness) }}
*/}}
{{- define "harbor-scanner-clair.probe" -}}
{{- $probe := deepCopy .probe -}}
{{- if and (include "harbor-scanner-clair.tls.enabled" .root) (hasKey $probe "httpGet") -}}
{{- if not (hasKey $probe.httpGet "scheme") -}}
{{- $_ := set $probe.httpGet "scheme" "HTTPS" -}}
{{- end -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end -}}

{{- define "harbor-scanner-clair.namespace" -}}
{{- .Release.Namespace -}}
{{- end -}}

{{/*
=============================================================================
Generic configuration passthrough
=============================================================================
*/}}

{{/*
Flatten a nested map into env-var assignments. Nested maps join with "_",
keys are uppercased, slices join with ",", and nil entries are skipped.
`isSecret` base64-encodes the values for a Secret's `data` block.

  config:
    scanner:
      clair:
        url: http://clair:6060   ->   SCANNER_CLAIR_URL: "http://clair:6060"

No prefix is imposed: the adapter also reads HTTP_PROXY, HTTPS_PROXY and
NO_PROXY, which a forced SCANNER_ prefix would put out of reach.
*/}}
{{- define "harbor-scanner-clair.toEnvVars" -}}
{{- $prefix := "" }}
{{- if .prefix }}{{- $prefix = printf "%s_" (.prefix | upper) }}{{- end }}
{{- range $key, $value := .values }}
{{- if kindIs "map" $value }}
{{- include "harbor-scanner-clair.toEnvVars" (dict "values" $value "prefix" (printf "%s%s" $prefix ($key | upper)) "isSecret" $.isSecret) }}
{{- else if kindIs "slice" $value }}
{{ $prefix }}{{ $key | upper }}: {{ if $.isSecret }}{{ $value | join "," | b64enc | quote }}{{ else }}{{ $value | join "," | quote }}{{ end }}
{{- else if not (kindIs "invalid" $value) }}
{{ $prefix }}{{ $key | upper }}: {{ if $.isSecret }}{{ $value | toString | b64enc | quote }}{{ else }}{{ $value | toString | quote }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Env var names claimed by .Values.config / .Values.secret, as a YAML list.

This exists because envFrom is evaluated BEFORE env: a chart-set `env` entry
always beats an envFrom source of the same name. Without dropping the chart's
own entry, anything the user set through the passthrough would be silently
ignored.
*/}}
{{- define "harbor-scanner-clair.claimedEnvNames" -}}
{{- $names := list -}}
{{- range $source := (list (.Values.config | default dict) (.Values.secret | default dict)) -}}
{{- range $name, $value := (include "harbor-scanner-clair.toEnvVars" (dict "values" $source "prefix" "" "isSecret" false) | fromYaml) -}}
{{- $names = append $names $name -}}
{{- end -}}
{{- end -}}
{{- toYaml $names -}}
{{- end -}}

{{/*
The container's final `env` list: the chart's own entries minus anything
claimed by config/secret, then extraEnv appended.

Precedence, lowest to highest:
  chart defaults  <  config / secret (envFrom)  <  extraEnv
extraEnv wins over the passthrough for free, because it lands in `env`.
*/}}
{{- define "harbor-scanner-clair.env" -}}
{{- $claimed := include "harbor-scanner-clair.claimedEnvNames" . | fromYamlArray -}}
{{- $env := list -}}
{{- range (include "harbor-scanner-clair.chartEnv" . | fromYamlArray) -}}
{{- if not (has .name $claimed) -}}
{{- $env = append $env . -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- $env = append $env . -}}
{{- end -}}
{{- toYaml $env -}}
{{- end -}}

{{/*
The chart's own environment, as a YAML list. Kept as data rather than
rendered inline so harbor-scanner-clair.env can drop any entry whose name
the user claimed through .Values.config / .Values.secret.
*/}}
{{- define "harbor-scanner-clair.chartEnv" -}}
{{- $tls := include "harbor-scanner-clair.tls.enabled" . -}}
{{- $extraCA := include "harbor-scanner-clair.extraCA.enabled" . -}}
{{- $pskSecret := include "harbor-scanner-clair.clair.pskSecretName" . -}}
- name: SCANNER_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
- name: SCANNER_API_SERVER_ADDR
  value: ":{{ .Values.service.port }}"
- name: SCANNER_API_SERVER_READ_TIMEOUT
  value: {{ .Values.api.readTimeout | quote }}
- name: SCANNER_API_SERVER_WRITE_TIMEOUT
  value: {{ .Values.api.writeTimeout | quote }}
- name: SCANNER_API_SERVER_IDLE_TIMEOUT
  value: {{ .Values.api.idleTimeout | quote }}
- name: SCANNER_API_SERVER_METRICS_ENABLED
  value: {{ .Values.metrics.enabled | quote }}
{{- if $tls }}
- name: SCANNER_API_SERVER_TLS_CERTIFICATE
  value: /certs/tls.crt
- name: SCANNER_API_SERVER_TLS_KEY
  value: /certs/tls.key
{{- end }}
- name: SCANNER_CLAIR_URL
  value: {{ .Values.clair.url | quote }}
{{- if $pskSecret }}
{{- /* The value is a credential, so it is read from the Secret rather than
       inlined into the pod spec. The PSK is base64 text and the Secret `data`
       layer base64-encodes it again: that double encoding is correct, because
       `data:` is always base64 of the raw value and the raw value here is
       itself base64, which is the form Clair's auth.psk.key takes. */}}
- name: SCANNER_CLAIR_PSK
  valueFrom:
    secretKeyRef:
      name: {{ $pskSecret }}
      key: {{ include "harbor-scanner-clair.clair.pskSecretKey" . }}
{{- end }}
- name: SCANNER_CLAIR_JWT_ISSUER
  value: {{ .Values.clair.jwtIssuer | quote }}
- name: SCANNER_CLAIR_INDEX_TIMEOUT
  value: {{ .Values.clair.indexTimeout | quote }}
- name: SCANNER_CLAIR_REQUEST_TIMEOUT
  value: {{ .Values.clair.requestTimeout | quote }}
{{- /* Unconditional, like the TTL and the concurrency below: the adapter's own
      defaults are real defaults, not a "derive it for me" signal, so the chart
      states what it wants rather than leaving the value to drift with the
      image. */}}
- name: SCANNER_STORE_BACKEND
  value: {{ .Values.store.backend | quote }}
{{- with (include "harbor-scanner-clair.postgres.secretName" .) }}
{{- /* Always a secretKeyRef, never a literal: the DSN carries the password in
       its userinfo. Emitted only on the postgres backend, so a memory install
       carries no dead reference to a Secret that need not exist. */}}
- name: SCANNER_STORE_POSTGRES_URL
  valueFrom:
    secretKeyRef:
      name: {{ . }}
      key: {{ include "harbor-scanner-clair.postgres.secretKey" $ }}
{{- end }}
- name: SCANNER_STORE_SCAN_JOB_TTL
  value: {{ .Values.store.scanJobTTL | quote }}
- name: SCANNER_JOB_QUEUE_WORKER_CONCURRENCY
  value: {{ .Values.jobQueue.workerConcurrency | quote }}
- name: SCANNER_TLS_INSECURE_SKIP_VERIFY
  value: {{ .Values.tls.insecureSkipVerify | quote }}
{{- with (include "harbor-scanner-clair.extraCA.certPaths" .) }}
{{- /* The adapter's own trust list: each named file is read and appended to
      the pool returned by x509.SystemCertPool. Only the named keys are
      reachable this way, which is why an empty extraCA.keys emits nothing
      and leans on SSL_CERT_DIR below instead. */}}
- name: SCANNER_TLS_CLIENTCAS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.httpProxy }}
- name: HTTP_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.httpsProxy }}
- name: HTTPS_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.noProxy }}
- name: NO_PROXY
  value: {{ . | quote }}
{{- end }}
{{- if $extraCA }}
{{- /* Go's crypto/x509 REPLACES its default directory list when SSL_CERT_DIR
      is set, so the system bundle has to be named explicitly or every public
      TLS call breaks. Order is irrelevant: a cert in any listed directory is
      trusted. */}}
- name: SSL_CERT_DIR
  value: "/etc/ssl/certs:/etc/scanner-clair/extra-ca"
{{- end }}
{{- end -}}

{{/*
=============================================================================
Extra CA trust
=============================================================================
*/}}

{{/*
Non-empty when a private CA bundle is mounted.
*/}}
{{- define "harbor-scanner-clair.extraCA.enabled" -}}
{{- if or .Values.extraCA.existingSecret .Values.extraCA.existingConfigMap -}}enabled{{- end -}}
{{- end -}}

{{/*
Comma-separated paths of the named CA files, for SCANNER_TLS_CLIENTCAS. Empty
when no bundle is mounted or when no keys are named.
*/}}
{{- define "harbor-scanner-clair.extraCA.certPaths" -}}
{{- if include "harbor-scanner-clair.extraCA.enabled" . -}}
{{- $paths := list -}}
{{- range .Values.extraCA.keys -}}
{{- $paths = append $paths (printf "/etc/scanner-clair/extra-ca/%s" .) -}}
{{- end -}}
{{- join "," $paths -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-clair.extraCA.volume" -}}
{{- if include "harbor-scanner-clair.extraCA.enabled" . }}
- name: extra-ca
  {{- if .Values.extraCA.existingSecret }}
  secret:
    secretName: {{ .Values.extraCA.existingSecret }}
  {{- else }}
  configMap:
    name: {{ .Values.extraCA.existingConfigMap }}
  {{- end }}
  {{- with .Values.extraCA.keys }}
    items:
      {{- range . }}
      - key: {{ . }}
        path: {{ . }}
      {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{- define "harbor-scanner-clair.extraCA.volumeMount" -}}
{{- if include "harbor-scanner-clair.extraCA.enabled" . }}
- name: extra-ca
  mountPath: /etc/scanner-clair/extra-ca
  readOnly: true
{{- end }}
{{- end -}}

{{/*
Number of scalar leaves in a nested map. Compared against the flattened key
count to detect names that collapse onto each other.
*/}}
{{- define "harbor-scanner-clair.countLeaves" -}}
{{- $count := 0 -}}
{{- range $key, $value := . -}}
{{- if kindIs "map" $value -}}
{{- $count = add $count (int (include "harbor-scanner-clair.countLeaves" $value)) -}}
{{- else if not (kindIs "invalid" $value) -}}
{{- $count = add $count 1 -}}
{{- end -}}
{{- end -}}
{{- $count -}}
{{- end -}}
