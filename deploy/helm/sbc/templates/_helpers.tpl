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

{{- define "sbc.postgresSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{/* Selector labels for the sbc-frontend (nginx) pod. Separate component
     so the frontend Deployment can be rolled without disturbing the
     SIP-serving daemon pod. */}}
{{- define "sbc.frontendSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: frontend
{{- end }}

{{/* Selector labels for the sbc-api-server pod. Separate component so
     the API-server Deployment rolls independently of the SIP-serving
     daemon and the nginx-served frontend. */}}
{{- define "sbc.apiSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{/* Selector labels for the sbc-provision-server pod. Phone provisioning
     rolls and recovers independently of SIP, the API, and the frontend.
     Phones re-fetch on their own boot cycle so a brief unavailability
     during a rolling update doesn't disrupt active calls. */}}
{{- define "sbc.provisionSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: provision
{{- end }}

{{/* Selector labels for the sbc-client-config-server pod. Soft-client
     discovery + provisioning (docs/CLIENT-PROVISIONING-OIDC.md); stateless,
     rolls independently of SIP — clients re-fetch config on their TTL. */}}
{{- define "sbc.clientConfigSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: client-config
{{- end }}

{{/* Selector labels for the sbc-announcement-server pod. Announcement
     media playback rolls and scales independently of SIP — the daemon
     falls back to in-process when the pod is absent. */}}
{{- define "sbc.announcementSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: announcement
{{- end }}

{{/* Selector labels for the sbc-trunk-agent pod. Trunk registration and
     OPTIONS health-probe loops run outside the daemon. Deploy exactly ONE
     replica — two agents would double-REGISTER to carriers. */}}
{{- define "sbc.trunkAgentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: trunk-agent
{{- end }}

{{- define "sbc.configSyncSelectorLabels" -}}
app.kubernetes.io/name: {{ include "sbc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: config-sync
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
# Outside zone faces the public internet (PSTN/SIP trunks). The pod's
# RFC1918 address is unreachable from carriers, so SDP must advertise the
# public NAT IP. "stun" tells the daemon to discover it at startup via
# STUN — carriers like BulkVS need this to route initial RTP packets
# rather than dropping them at our SDP'd private IP and waiting to latch
# on outgoing RTP (which causes audible crackle as the jitter buffer
# recovers).
external_ip = "stun"

[[zones]]
name = "oobm"
signaling_interface = "__POD_IP__"
media_interface = "__POD_IP__"
external_ip = "__POD_IP__"

[transport]
# All SIP listeners are dual-stack wildcards: one socket serves IPv4 and
# IPv6 (IPV6_V6ONLY=0). Required for the v6 anycast SIP VIP
# (site.sbc_lb_ip6) — soft clients prefer AAAA. uc-transport canonicalizes
# IPv4-mapped UDP sources; stream connections may log v4 peers in
# ::ffff:a.b.c.d form, which is cosmetic.
udp_listen = ["[::]:5060"]
tcp_listen = ["[::]:5060"]
tls_listen = ["[::]:5061"]
ws_listen = []
wss_listen = []
tcp_timeout_secs = 30
tcp_idle_timeout_secs = 300
api_listen = {{ .Values.sbcDaemon.config.api_listen | quote }}
{{- if .Values.sbcDaemon.sipTls.secretName }}
# With security.tls_cert_path set, the API server would otherwise switch its
# main listener to HTTPS (legacy single-listener mode) and break the chart's
# HTTP services/probes. Naming an HTTPS address keeps HTTP on api_listen and
# serves HTTPS side-by-side here.
api_tls_listen = "0.0.0.0:8443"
{{- end }}

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
{{- if .Values.sbcDaemon.sipTls.secretName }}
# SIP-over-TLS server credentials (Secret {{ .Values.sbcDaemon.sipTls.secretName }})
tls_cert_path = "/etc/sbc/sip-tls/tls.crt"
tls_key_path = "/etc/sbc/sip-tls/tls.key"
{{- end }}

[monitoring]
metrics_bind = {{ .Values.sbcDaemon.config.metrics_listen | quote }}
per_call_metrics = false
scrape_interval_secs = 15

[grpc]
# gRPC admin API. Used by sbc-api-server (when sbcApi.enabled) to call
# TrunkSync / DialPlanSync / DidMappingSync after operator writes, so
# the SIP router stays in sync without sbc-api going through the
# daemon's REST endpoint. Distinct port from `[monitoring]` above —
# both default to 9090 in the Rust schema, which would collide.
# `enabled` defaults to false in the schema, so it MUST be set true
# here or the gRPC server never starts and sbc-api's writes silently
# skip the SIP-router refresh step.
enabled = true
listen_addr = {{ .Values.sbcDaemon.config.grpc_listen | quote }}
enable_reflection = false
require_mtls = false

# Phone provisioning HTTP server. Without this section the daemon leaves
# AppState::provisioning = None and /provision/<MAC>.{cfg,xml} returns 503.
# `host` is the FQDN that gets embedded in vendor configs as the next-fetch
# URL — phones come back here after first boot for refresh checks.
[provisioning]
host = {{ printf "sbc.%s" .Values.site.fqdn_base | quote }}
port = 80

[rate_limit]
enabled = true
global_rps = 10000
per_ip_rps = 10000
per_user_rps = 50
burst_multiplier = 2.0
{{- if .Values.sbcDaemon.topologyHiding.enabled }}

# Topology hiding (SC-7): anonymize the SBC's internal signaling host in the
# Via/Contact of outbound trunk-facing INVITEs. Applies only to outside-facing
# (trunk/carrier) legs; inside-facing legs are never rewritten.
[topology_hiding]
enabled = true
mode = {{ .Values.sbcDaemon.topologyHiding.mode | quote }}
external_host = {{ .Values.sbcDaemon.topologyHiding.externalHost | default (printf "sbc.%s" .Values.site.fqdn_base) | quote }}
external_port = {{ .Values.sbcDaemon.topologyHiding.externalPort }}
obfuscate_call_id = {{ .Values.sbcDaemon.topologyHiding.obfuscateCallId }}
{{- end }}

[logging]
level = "info"
format = "json"
output = "stdout"
audit_enabled = true
{{- end }}
