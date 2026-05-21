{{/* Chart name */}}
{{- define "sbc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Per-site fully-qualified name (chart name + site name) */}}
{{- define "sbc.fullname" -}}
{{- printf "%s-%s" (include "sbc.name" .) .Values.site.name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sbc.labels" -}}
helm.sh/chart: {{ include "sbc.chart" . }}
{{ include "sbc.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
sbc.usg/site: {{ .Values.site.name }}
{{- end }}

{{- define "sbc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: daemon
{{- end }}

{{- define "sbc.keaSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: kea-dhcp4
{{- end }}

{{/* Selector labels for the sbc-frontend (nginx) pod. Separate component
     so the frontend Deployment can be rolled without disturbing the
     SIP-serving daemon pod. */}}
{{- define "sbc.frontendSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: frontend
{{- end }}

{{- define "sbc.serviceAccountName" -}}
{{ include "sbc.fullname" . }}
{{- end }}

{{/*
Render the sbc-daemon config.toml. All three zones share the SBC's pinned
pod IP — the daemon binds once to 0.0.0.0:5060 and classifies zone post-
receive (trunk-peer match, dial-plan match) rather than by which local IP
the packet hit. external_ip is the same as signaling for SDP c=/Via/Contact.
*/}}
{{- define "sbc.config" -}}
[general]
instance_name = {{ .Values.site.name | quote }}
max_calls = {{ .Values.sbcDaemon.config.max_calls }}
max_registrations = {{ .Values.sbcDaemon.config.max_registrations }}

[[zones]]
name = "inside"
signaling_interface = "__POD_IP__"
media_interface = "__POD_IP__"
external_ip = "__POD_IP__"

[[zones]]
name = "outside"
signaling_interface = "__POD_IP__"
media_interface = "__POD_IP__"
external_ip = "__POD_IP__"

[[zones]]
name = "oobm"
signaling_interface = "__POD_IP__"
media_interface = "__POD_IP__"
external_ip = "__POD_IP__"

[transport]
udp_listen = ["0.0.0.0:5060"]
tcp_listen = ["0.0.0.0:5060"]
tls_listen = ["0.0.0.0:5061"]
ws_listen = []
wss_listen = []
tcp_timeout_secs = 30
tcp_idle_timeout_secs = 300
api_listen = {{ .Values.sbcDaemon.config.api_listen | quote }}

[media]
default_mode = {{ .Values.sbcDaemon.config.media_mode | quote }}
codecs = ["Opus", "G722", "G711Ulaw", "G711Alaw"]
rtp_port_min = 16384
rtp_port_max = 32768

[media.srtp]
required = {{ .Values.sbcDaemon.config.srtp_required }}
profile = "AeadAes256Gcm"

[media.dtls]
fingerprint_hash = "Sha384"

[security]
curve = "P384"
min_tls_version = "1.3"
require_mtls = false

[monitoring]
metrics_bind = {{ .Values.sbcDaemon.config.metrics_listen | quote }}
per_call_metrics = false
scrape_interval_secs = 15

[rate_limit]
enabled = true
global_rps = 10000
per_ip_rps = 10000
per_user_rps = 50
burst_multiplier = 2.0

[logging]
level = "info"
format = "json"
output = "stdout"
audit_enabled = true
{{- end }}

{{/*
Render kea-dhcp4.conf. Phone subnets keyed by relay agent IP (giaddr).
*/}}
{{- define "kea.config" -}}
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": ["eth0"] },
    "lease-database": { "type": "memfile", "persist": false },
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    "subnet4": [
      {{- range $i, $sub := .Values.kea.phone_subnets }}
      {{- if $i }},{{ end }}
      {
        "id": {{ add $i 1 }},
        "subnet": {{ $sub.subnet | quote }},
        "pools":  [{ "pool": {{ printf "%s - %s" (index $sub.pool 0) (index $sub.pool 1) | quote }} }],
        "option-data": [
          { "name": "routers",          "data": {{ $sub.gateway | quote }} },
          { "name": "tftp-server-name", "data": {{ $sub.tftp_server | quote }} }
          {{- with $sub.dns_servers }},
          { "name": "domain-name-servers", "data": {{ join "," . | quote }} }
          {{- end }}
        ],
        "relay": { "ip-addresses": [{{ $sub.gateway | quote }}] }
      }
      {{- end }}
    ]
  }
}
{{- end }}
