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

{{/* The Postgres DSN env var: from the bundled secret or an external one. */}}
{{- define "central-config.dsnEnv" -}}
- name: CENTRAL_POSTGRES_URL
  valueFrom:
    secretKeyRef:
{{- if .Values.postgres.enabled }}
      name: {{ include "central-config.fullname" . }}-postgres
      key: dsn
{{- else }}
      name: {{ required "postgres.existingSecret.name required when postgres.enabled=false" .Values.postgres.existingSecret.name }}
      key: {{ .Values.postgres.existingSecret.key | default "dsn" }}
{{- end }}
{{- end }}
