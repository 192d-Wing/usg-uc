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

[logging]
level = "info"
format = "json"
output = "stdout"
audit_enabled = true
{{- end }}

{{/*
Build the TEO TSG DHCP option 125 (VIVSO) hex payload for a phone subnet.
Format observed in the field (commit 6e01e32):

  | 4 bytes magic header (0x99CCCA4C) | ASCII key=value;key=value;... |

The ASCII payload's exact spacing/casing matters — TSG firmware does
strict string matching, so quirks from the reference config are
preserved (notably the space after some semicolons like `; Protocol=` and
`; SipProxyPort=`).

Argument: a single phone_subnet entry (with .vlan_id and .tftp_server)
plus the parent `$` context (for site.fqdn_base).
*/}}
{{- define "teo.option125Hex" -}}
{{- $sub := .sub -}}
{{- $host := $sub.tftp_server -}}
{{- $vlan := $sub.vlan_id | int -}}
{{- $payload := printf "L2Q=1;L2QVLAN=%d;VoicePri=2;SignalPri=3;UpdateSrvr=%s;Protocol=HTTP;ConfigFile=MAC;SipProxySrvr=%s;SipProxyPort=5060;SipRegistrar=%s;SipRegPort=5060;ServerType=TEO_UCM" $vlan $host $host $host -}}
{{- /* Magic header */ -}}
0x99CCD3
{{- /* ASCII payload, byte-by-byte to uppercase hex. Sprig's `range` can't
       iterate a string, so we walk indices with `until (len ...)` and use
       `index` which returns the byte value at that position. ASCII-only
       payload, so byte == codepoint. */ -}}
{{- $len := len $payload -}}
{{- range $i := until $len -}}{{- printf "%02X" (index $payload $i) -}}{{- end -}}
{{- end -}}

{{/*
Render kea-dhcp4.conf. Phone subnets keyed by relay agent IP (giaddr).

Option 125 (VIVSO) is a Kea built-in (`vivso-suboptions`) whose option-data
path validates the payload as RFC 3925 sub-options even when csv-format is
false — so Kea rejects the TEO blob ("Option parse failed. Tried to parse
84 bytes from 247-byte long buffer."). We instead use the flex_option hook
library to inject raw bytes into option 125 unconditionally for any client
that lands in this server, which is what the original (pre-Helm) Kea
configmap did and what TEO TSG firmware expects.

Scoping: flex_option is a server-level hook, not subnet-level. All subnets
in this chart are phone subnets so unconditional injection is fine; if a
mixed deployment ever needs per-subnet scoping, add a `client-class`
expression matching the subnet's giaddr.
*/}}
{{- define "kea.config" -}}
{{- $teoSubnets := list -}}
{{- range $sub := .Values.kea.phone_subnets -}}
  {{- if and $sub.teo_option_125 $sub.teo_option_125.enabled -}}
    {{- $teoSubnets = append $teoSubnets $sub -}}
  {{- end -}}
{{- end -}}
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": ["eth0"] },
    "lease-database": { "type": "memfile", "persist": false },
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    {{- if $teoSubnets }}
    "hooks-libraries": [
      {
        "library": "/usr/local/lib/kea/hooks/libdhcp_flex_option.so",
        "parameters": {
          "options": [
            {
              "code": 125,
              "add": {{ include "teo.option125Hex" (dict "sub" (index $teoSubnets 0)) | quote }}
            }
          ]
        }
      }
    ],
    {{- end }}
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
