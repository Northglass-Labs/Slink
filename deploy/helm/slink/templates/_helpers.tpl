{{/*
Expand the name of the chart.
*/}}
{{- define "slink.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Truncated to 63 chars for label compliance.
If `release-name` already contains the chart name, don't double-prefix.
*/}}
{{- define "slink.fullname" -}}
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

{{/*
Component-specific names — keeps API and frontend resources distinct.
*/}}
{{- define "slink.api.fullname" -}}
{{ include "slink.fullname" . }}-api
{{- end -}}

{{- define "slink.frontend.fullname" -}}
{{ include "slink.fullname" . }}-frontend
{{- end -}}

{{- define "slink.migrate.fullname" -}}
{{ include "slink.fullname" . }}-migrate
{{- end -}}

{{/*
Chart label string `<name>-<version>`, sanitized for k8s.
*/}}
{{- define "slink.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels — applied to every object. `app.kubernetes.io/component` is
added per-template (api, frontend, migrate, etc.).
*/}}
{{- define "slink.labels" -}}
helm.sh/chart: {{ include "slink.chart" . }}
{{ include "slink.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: slink
{{- end -}}

{{/*
Selector labels — used in deployment selectors and service selectors.
NOTE: these are stable across upgrades; never add fields that change between
releases (e.g. version) or selectors will detach from running pods.
*/}}
{{- define "slink.selectorLabels" -}}
app.kubernetes.io/name: {{ include "slink.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name to use.
*/}}
{{- define "slink.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "slink.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Resolve the out-of-band Secret used by the application. The chart never renders
credential values into Helm release state.
*/}}
{{- define "slink.secretName" -}}
{{- if ne (int .Values.api.replicas) 1 -}}
{{- fail "api.replicas must remain 1 until scheduler leader election is implemented" -}}
{{- end -}}
{{- if and .Values.postgresql.enabled (not .Values.postgresql.auth.existingSecret) -}}
{{- fail "postgresql.auth.existingSecret is required when bundled PostgreSQL is enabled" -}}
{{- end -}}
{{- required "existingSecret is required; create it out-of-band before rendering Slink" .Values.existingSecret -}}
{{- end -}}

{{/*
Image reference helper — handles registry/repo/tag splits and pullPolicy.
Usage: {{ include "slink.image" (dict "image" .Values.api.image "global" .Values.image) }}
*/}}
{{- define "slink.image" -}}
{{- $registry := .global.registry | default "" -}}
{{- $repo := .image.repository -}}
{{- $digest := required "image.digest is required; deploy the release by sha256 digest" .image.digest -}}
{{- if $registry -}}
{{- printf "%s/%s@%s" $registry $repo $digest -}}
{{- else -}}
{{- printf "%s@%s" $repo $digest -}}
{{- end -}}
{{- end -}}

{{/*
Standard env-from block — pulls every key in the secret into the container env.
Both api and migrate use this. Keep it in one place so the secret schema only
has to be documented once.
*/}}
{{- define "slink.envFrom" -}}
- secretRef:
    name: {{ include "slink.secretName" . }}
- configMapRef:
    name: {{ include "slink.fullname" . }}-config
{{- end -}}
