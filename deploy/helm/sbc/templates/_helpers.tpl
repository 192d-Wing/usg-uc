{{/*
Expand the name of the chart.
*/}}
{{- define "sbc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sbc.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sbc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sbc.labels" -}}
helm.sh/chart: {{ include "sbc.chart" . }}
{{ include "sbc.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sbc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: daemon
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sbc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sbc.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate the config.toml content
*/}}
{{- define "sbc.config" -}}
[general]
instance_name = {{ .Values.config.general.instanceName | quote }}
max_calls = {{ .Values.config.general.maxCalls }}
max_registrations = {{ .Values.config.general.maxRegistrations }}

[transport]
udp_listen = {{ .Values.config.transport.udpListen | toJson }}
tcp_listen = {{ .Values.config.transport.tcpListen | toJson }}
tls_listen = {{ .Values.config.transport.tlsListen | toJson }}
ws_listen = {{ .Values.config.transport.wsListen | toJson }}
wss_listen = {{ .Values.config.transport.wssListen | toJson }}
tcp_timeout_secs = {{ .Values.config.transport.tcpTimeoutSecs }}
tcp_idle_timeout_secs = {{ .Values.config.transport.tcpIdleTimeoutSecs }}

[media]
default_mode = {{ .Values.config.media.defaultMode | quote }}
codecs = {{ .Values.config.media.codecs | toJson }}
rtp_port_min = {{ .Values.config.media.rtpPortMin }}
rtp_port_max = {{ .Values.config.media.rtpPortMax }}

[media.srtp]
required = {{ .Values.config.media.srtp.required }}
profile = {{ .Values.config.media.srtp.profile | quote }}

[media.dtls]
fingerprint_hash = {{ .Values.config.media.dtls.fingerprintHash | quote }}

[security]
curve = {{ .Values.config.security.curve | quote }}
min_tls_version = {{ .Values.config.security.minTlsVersion | quote }}
require_mtls = {{ .Values.config.security.requireMtls }}

[stir_shaken]
signing_enabled = {{ .Values.config.stirShaken.signingEnabled }}
verification_enabled = {{ .Values.config.stirShaken.verificationEnabled }}
default_attestation = {{ .Values.config.stirShaken.defaultAttestation | quote }}
max_passport_age_secs = {{ .Values.config.stirShaken.maxPassportAgeSecs }}

[rate_limit]
enabled = {{ .Values.config.rateLimit.enabled }}
global_rps = {{ .Values.config.rateLimit.globalRps }}
per_ip_rps = {{ .Values.config.rateLimit.perIpRps }}
per_user_rps = {{ .Values.config.rateLimit.perUserRps }}
burst_multiplier = {{ .Values.config.rateLimit.burstMultiplier }}

[logging]
level = {{ .Values.config.logging.level | quote }}
format = {{ .Values.config.logging.format | quote }}
output = {{ .Values.config.logging.output | quote }}
audit_enabled = {{ .Values.config.logging.auditEnabled }}
{{- end }}
