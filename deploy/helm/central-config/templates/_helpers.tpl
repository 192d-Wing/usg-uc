{{- define "central-config.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "central-config.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "central-config.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{- define "central-config.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "central-config.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "central-config.apiSelectorLabels" -}}
app.kubernetes.io/name: {{ include "central-config.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{- define "central-config.pgSelectorLabels" -}}
app.kubernetes.io/name: {{ include "central-config.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{- define "central-config.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "central-config.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{/* The CloudNativePG Cluster name (its -rw/-ro/-r Services derive from it). */}}
{{- define "central-config.cnpgName" -}}
{{- printf "%s-pg" (include "central-config.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
  Database env for the API: the read-write CENTRAL_POSTGRES_URL, an optional
  read-only CENTRAL_POSTGRES_RO_URL (which enables the read/write split), and
  the per-pool connection cap. Sourced per `postgres.mode`:
    bundled  — one Secret, dsn only (no replica; reads use the primary).
    cnpg     — our owned Secret with dsn (-rw) and dsnRo (-ro).
    external — existingSecret.key for RW, optional existingSecret.roKey for RO.
*/}}
{{- define "central-config.dsnEnv" -}}
{{- $mode := .Values.postgres.mode | default "bundled" -}}
- name: CENTRAL_POSTGRES_URL
  valueFrom:
    secretKeyRef:
{{- if eq $mode "bundled" }}
      name: {{ include "central-config.fullname" . }}-postgres
      key: dsn
{{- else if eq $mode "cnpg" }}
      name: {{ include "central-config.fullname" . }}-cnpg
      key: dsn
- name: CENTRAL_POSTGRES_RO_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "central-config.fullname" . }}-cnpg
      key: dsnRo
{{- else if eq $mode "external" }}
      name: {{ required "postgres.existingSecret.name required when postgres.mode=external" .Values.postgres.existingSecret.name }}
      key: {{ .Values.postgres.existingSecret.key | default "dsn" }}
{{- if .Values.postgres.existingSecret.roKey }}
- name: CENTRAL_POSTGRES_RO_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.existingSecret.name }}
      key: {{ .Values.postgres.existingSecret.roKey }}
{{- end }}
{{- else }}
{{- fail (printf "postgres.mode must be bundled|cnpg|external, got %q" $mode) }}
{{- end }}
- name: CENTRAL_PG_MAX_CONNS
  value: {{ .Values.postgres.maxConnections | default 10 | quote }}
{{- end }}
