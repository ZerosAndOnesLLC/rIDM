{{/* Chart name, truncated to the 63 characters a label allows. */}}
{{- define "ridm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name: the release name, plus the chart's unless it already contains it. */}}
{{- define "ridm.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ridm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ridm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ridm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ridm.labels" -}}
helm.sh/chart: {{ include "ridm.chart" . }}
{{ include "ridm.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ridm
{{- end }}

{{- define "ridm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ridm.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ridm.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end }}
{{- end }}

{{/*
Every secret variable the server reads: its name, the inline value and the
reference to a caller's Secret. A reference with a name wins; an inline value
goes into the chart's own Secret under the variable's name.
*/}}
{{- define "ridm.secretItems" -}}
{{- $v := .Values -}}
- {env: DATABASE_URL, value: {{ $v.database.url | quote }}, ref: {{ toJson $v.database.existingSecret }}}
- {env: DATABASE_READ_URL, value: {{ $v.database.readUrl | quote }}, ref: {{ toJson $v.database.readExistingSecret }}}
- {env: REDIS_URL, value: {{ $v.redis.url | quote }}, ref: {{ toJson $v.redis.existingSecret }}}
- {env: MASTER_KEY, value: {{ $v.masterKey.value | quote }}, ref: {{ toJson $v.masterKey.existingSecret }}}
- {env: MASTER_KEY_PREVIOUS, value: {{ $v.masterKey.previous | quote }}, ref: {{ toJson $v.masterKey.previousExistingSecret }}}
- {env: SMTP_PASSWORD, value: {{ $v.smtp.password | quote }}, ref: {{ toJson $v.smtp.existingSecret }}}
- {env: METRICS_TOKEN, value: {{ $v.metrics.token | quote }}, ref: {{ toJson $v.metrics.existingSecret }}}
{{- if $v.bootstrap.enabled }}
- {env: BOOTSTRAP_ADMIN_PASSWORD, value: {{ $v.bootstrap.adminPassword | quote }}, ref: {{ toJson $v.bootstrap.existingSecret }}}
{{- end }}
{{- end }}

{{/* The inline secret values, as a map from variable name to value. */}}
{{- define "ridm.inlineSecrets" -}}
{{- $out := dict -}}
{{- range (include "ridm.secretItems" . | fromYamlArray) -}}
{{- if and .value (not .ref.name) -}}
{{- $_ := set $out .env .value -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end }}

{{/* One env entry for a secret variable, or nothing when it is unset. `secret` is the Secret inline values live in. */}}
{{- define "ridm.secretEnv" -}}
{{- if .item.ref.name }}
- name: {{ .item.env }}
  valueFrom:
    secretKeyRef:
      name: {{ .item.ref.name }}
      key: {{ default .item.env .item.ref.key }}
{{- else if .item.value }}
- name: {{ .item.env }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: {{ .item.env }}
{{- end }}
{{- end }}

{{/*
The master key as a mounted file (masterKey.asFile): the volume, from the
caller's Secret or `secret` (where an inline key lives).
*/}}
{{- define "ridm.masterKeyVolume" -}}
{{- $ref := .root.Values.masterKey.existingSecret -}}
- name: master-key
  secret:
    secretName: {{ ternary $ref.name .secret (not (empty $ref.name)) }}
    items:
      - key: {{ ternary (default "MASTER_KEY" $ref.key) "MASTER_KEY" (not (empty $ref.name)) }}
        path: master-key
    # Readable through the pod's fsGroup, by nobody else.
    defaultMode: 0440
{{- end }}

{{/* Refuse to render a release that cannot start. */}}
{{- define "ridm.validate" -}}
{{- $v := .Values -}}
{{- if not $v.publicUrl -}}
{{- fail "publicUrl is required: the externally visible base URL, e.g. https://id.example.com" -}}
{{- end -}}
{{- if not (regexMatch "^https?://" $v.publicUrl) -}}
{{- fail "publicUrl must be an http or https URL" -}}
{{- end -}}
{{- if not (or $v.database.url $v.database.existingSecret.name) -}}
{{- fail "database.url or database.existingSecret.name is required" -}}
{{- end -}}
{{- if not (or $v.redis.url $v.redis.existingSecret.name) -}}
{{- fail "redis.url or redis.existingSecret.name is required" -}}
{{- end -}}
{{- if not (or $v.masterKey.value $v.masterKey.existingSecret.name) -}}
{{- fail "masterKey.value or masterKey.existingSecret.name is required (openssl rand -hex 32)" -}}
{{- end -}}
{{- if and $v.migrations.enabled (not (or $v.migrations.database.url $v.migrations.database.existingSecret.name)) -}}
{{- fail "migrations.database.url or migrations.database.existingSecret.name is required (a role that owns the schema), or set migrations.enabled=false" -}}
{{- end -}}
{{- if and $v.bootstrap.enabled (not $v.bootstrap.adminEmail) -}}
{{- fail "bootstrap.adminEmail is required when bootstrap.enabled" -}}
{{- end -}}
{{- if and $v.bootstrap.enabled (not (or $v.bootstrap.adminPassword $v.bootstrap.existingSecret.name)) -}}
{{- fail "bootstrap.adminPassword or bootstrap.existingSecret.name is required when bootstrap.enabled" -}}
{{- end -}}
{{- end }}

{{/* Plain (non-secret) environment, shared by the pods and the migration Job. */}}
{{- define "ridm.plainEnv" -}}
{{- $v := .Values -}}
PUBLIC_URL: {{ $v.publicUrl | quote }}
{{- with $v.uiUrl }}
UI_URL: {{ . | quote }}
{{- end }}
EMBEDDED_UI: {{ $v.embeddedUi | quote }}
BIND_ADDR: "0.0.0.0:8080"
TRUSTED_PROXIES: {{ $v.trustedProxies | quote }}
COOKIE_SECURE: {{ $v.cookieSecure | quote }}
LOG_FORMAT: {{ $v.logFormat | quote }}
RUST_LOG: {{ $v.logLevel | quote }}
DOCS_ENABLED: {{ $v.docsEnabled | quote }}
MIGRATE_ON_START: {{ $v.migrateOnStart | quote }}
DB_POOL_MIN: {{ $v.database.poolMin | quote }}
DB_POOL_MAX: {{ $v.database.poolMax | quote }}
REDIS_POOL_MAX: {{ $v.redis.poolMax | quote }}
MASTER_KEY_VERSION: {{ $v.masterKey.version | quote }}
{{- if $v.smtp.host }}
SMTP_HOST: {{ $v.smtp.host | quote }}
SMTP_PORT: {{ $v.smtp.port | quote }}
SMTP_SECURITY: {{ $v.smtp.security | quote }}
SMTP_FROM: {{ required "smtp.from is required with smtp.host" $v.smtp.from | quote }}
{{- with $v.smtp.username }}
SMTP_USERNAME: {{ . | quote }}
{{- end }}
{{- end }}
{{- if $v.bootstrap.enabled }}
BOOTSTRAP_ADMIN_EMAIL: {{ $v.bootstrap.adminEmail | quote }}
BOOTSTRAP_ADMIN_USERNAME: {{ $v.bootstrap.adminUsername | quote }}
{{- end }}
{{- range $k, $val := $v.env }}
{{ $k }}: {{ $val | toString | quote }}
{{- end }}
{{- end }}
