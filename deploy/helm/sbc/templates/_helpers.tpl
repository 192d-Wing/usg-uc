{{/* Chart name */}}
{{- define "sbc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Per-site fully-qualified name (chart name + site name) */}}
{{- define "sbc.fullname" -}}
{{- printf "%s-%s" (include "sbc.name" .) .Values.site.name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Secret with the daemon gRPC server certificate (sbcDaemon.grpcMtls). */}}
{{- define "sbc.grpcServerTlsSecret" -}}
{{- .Values.sbcDaemon.grpcMtls.serverSecretName | default (printf "%s-grpc-server-tls" (include "sbc.fullname" .)) -}}
{{- end }}

{{/* Secret with the sbc-api gRPC client certificate (sbcDaemon.grpcMtls). */}}
{{- define "sbc.grpcClientTlsSecret" -}}
{{- .Values.sbcDaemon.grpcMtls.clientSecretName | default (printf "%s-grpc-client-tls" (include "sbc.fullname" .)) -}}
{{- end }}

{{/* Secret with the sbc-trunk-agent gRPC client certificate (sbcDaemon.grpcMtls). */}}
{{- define "sbc.grpcTrunkAgentClientTlsSecret" -}}
{{- .Values.sbcDaemon.grpcMtls.trunkAgentClientSecretName | default (printf "%s-grpc-trunk-agent-tls" (include "sbc.fullname" .)) -}}
{{- end }}

{{/* TOML array for grpc.allowed_client_names (sbcDaemon.grpcMtls). Default:
     the sbc-api client CN, plus the trunk-agent client CN when the agent is
     enabled. */}}
{{- define "sbc.grpcAllowedClientNames" -}}
{{- $default := list (printf "%s-sbc-api" (include "sbc.fullname" .)) -}}
{{- if .Values.sbcTrunkAgent.enabled -}}
{{- $default = append $default (printf "%s-sbc-trunk-agent" (include "sbc.fullname" .)) -}}
{{- end -}}
{{- $names := .Values.sbcDaemon.grpcMtls.allowedClientNames | default $default -}}
[{{- range $i, $n := $names }}{{ if $i }}, {{ end }}{{ $n | quote }}{{ end -}}]
{{- end -}}

{{/* Daemon gRPC listen address. With sbcDaemon.grpcMtls the configured
     sbcDaemon.config.grpc_listen (default 0.0.0.0:9091); without it the
     listener is loopback only, because the daemon refuses a plaintext
     listener off loopback (NIST 800-53 Rev5: AC-3, SC-7, SC-8). */}}
{{- define "sbc.grpcListen" -}}
{{- $listen := .Values.sbcDaemon.config.grpc_listen | default "" -}}
{{- if .Values.sbcDaemon.grpcMtls.enabled -}}
{{- $listen | default "0.0.0.0:9091" -}}
{{- else if $listen -}}
{{- $listen -}}
{{- else -}}
127.0.0.1:9091
{{- end -}}
{{- end }}

{{/* SR-33: the outside zone's external_ip is required and is never bare
     "stun" (there is no default STUN server). Included from
     11-sbc-configmap.yaml. */}}
{{- define "sbc.outsideExternalIpPreflight" -}}
{{- $ext := .Values.sbcDaemon.config.outside_external_ip | default "" | toString -}}
{{- if or (eq $ext "") (eq $ext "stun") -}}
{{- fail "sbcDaemon.config.outside_external_ip is required: the outside zone's public IP, or \"stun:<ip>:<port>\" for an operator-run STUN server (there is no default STUN server)" -}}
{{- end -}}
{{- end }}

{{/* Render-time checks for the daemon gRPC settings (included from
     13-sbc-services.yaml and 26-sbc-grpc-mtls.yaml). */}}
{{- define "sbc.grpcMtlsPreflight" -}}
{{- $m := .Values.sbcDaemon.grpcMtls -}}
{{- if $m.enabled -}}
{{- $secrets := and $m.serverSecretName $m.clientSecretName (or (not .Values.sbcTrunkAgent.enabled) $m.trunkAgentClientSecretName) -}}
{{- if not (or $m.clusterIssuer $secrets) -}}
{{- fail "sbcDaemon.grpcMtls.enabled requires sbcDaemon.grpcMtls.clusterIssuer (cert-manager) or explicit serverSecretName/clientSecretName (plus trunkAgentClientSecretName when sbcTrunkAgent.enabled); see DEPLOYING.md \"Daemon gRPC mTLS\"" -}}
{{- end -}}
{{- else -}}
{{- if .Values.sbcApi.enabled -}}
{{- fail "sbcDaemon.grpcMtls.enabled=false requires sbcApi.enabled=false: sbc-api reaches the daemon gRPC over the pod network, and without mTLS the daemon serves gRPC on loopback only" -}}
{{- end -}}
{{- if .Values.sbcTrunkAgent.enabled -}}
{{- fail "sbcDaemon.grpcMtls.enabled=false requires sbcTrunkAgent.enabled=false: the trunk agent reaches the daemon gRPC over the pod network, and without mTLS the daemon serves gRPC on loopback only" -}}
{{- end -}}
{{- $listen := .Values.sbcDaemon.config.grpc_listen | default "" -}}
{{- if and $listen (not (regexMatch "^(127\\.[0-9.]+|\\[::1\\]):[0-9]+$" $listen)) -}}
{{- fail (printf "sbcDaemon.config.grpc_listen %q is not a loopback address; without sbcDaemon.grpcMtls the daemon gRPC listener must be loopback (leave grpc_listen empty or set 127.0.0.1:<port>)" $listen) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* Render-time checks for client-address trust (included from
     13-sbc-services.yaml). A trusted-proxy range is sound only while the
     NetworkPolicy limits who can reach sbc-api and provisioning, and nginx
     real_ip is sound only while the frontend is reachable from the edge
     proxies alone (NIST 800-53 Rev5: SC-7, SI-10). */}}
{{- define "sbc.clientAddressPreflight" -}}
{{- $np := .Values.networkPolicy -}}
{{- $proxies := or .Values.sbcProvision.trustedProxies .Values.sbcApi.trustedProxies -}}
{{- if and $proxies (not $np.enabled) (not $np.trustedProxiesWithoutPolicy) -}}
{{- fail "sbcProvision.trustedProxies / sbcApi.trustedProxies require networkPolicy.enabled=true: without it any pod in those ranges can set X-Real-IP. Set networkPolicy.trustedProxiesWithoutPolicy=true only if another control limits access to these pods to the frontend" -}}
{{- end -}}
{{- if and .Values.sbcFrontend.realIpFrom $np.enabled (not $np.edgeFrom) -}}
{{- fail "sbcFrontend.realIpFrom requires networkPolicy.edgeFrom: list the edge proxy (ingress controller / Gateway) peers so only they can reach the frontend and set X-Forwarded-For" -}}
{{- end -}}
{{- end }}

{{/* Daemon gRPC URL for in-cluster clients (https when grpcMtls is on; the
     -grpc Service exists only then). */}}
{{- define "sbc.daemonGrpcUrl" -}}
{{- printf "%s://%s-grpc.%s.svc.cluster.local:9091" (ternary "https" "http" .Values.sbcDaemon.grpcMtls.enabled) (include "sbc.fullname" .) .Release.Namespace -}}
{{- end }}

{{/* SR-53 edge TLS. Hostname of the Traefik Ingress (dashboard, login,
     client-config). */}}
{{- define "sbc.ingressHost" -}}
{{- .Values.sbcClientConfig.ingressHost | default (printf "sbc.%s" .Values.site.fqdn_base) -}}
{{- end }}

{{/* Traefik kubernetescrd ref of a chart-owned CRD object
     ("<namespace>-<fullname>-<suffix>@kubernetescrd"). */}}
{{- define "sbc.edgeCrdRef" -}}
{{- printf "%s-%s-%s@kubernetescrd" .ctx.Release.Namespace (include "sbc.fullname" .ctx) .suffix -}}
{{- end }}

{{/* TLSOption for the Ingress router: the chart's -cnsa object, or the
     operator's edge.traefik.tlsOption when createTlsOption=false (the
     empty-ref check is in 22-sbc-ingress.yaml). */}}
{{- define "sbc.edgeTlsOptionRef" -}}
{{- if .Values.edge.traefik.createTlsOption -}}
{{- include "sbc.edgeCrdRef" (dict "ctx" . "suffix" "cnsa") -}}
{{- else -}}
{{- .Values.edge.traefik.tlsOption -}}
{{- end -}}
{{- end }}

{{/* HSTS headers middleware for the Ingress router. */}}
{{- define "sbc.edgeHstsRef" -}}
{{- include "sbc.edgeCrdRef" (dict "ctx" . "suffix" "hsts") -}}
{{- end }}

{{/* Edge flag type checks, included from 16-sbc-frontend.yaml and
     22-sbc-ingress.yaml before either reads the flags. A string "false"
     is truthy in templates and would turn cleartext modes on, so only
     booleans are accepted (NIST 800-53 Rev5: CM-6, SC-8). */}}
{{- define "sbc.edgePreflight" -}}
{{- $flags := dict
    "edge.insecureLabHttp" .Values.edge.insecureLabHttp
    "edge.traefik.allowHttpProvisioning" .Values.edge.traefik.allowHttpProvisioning
    "edge.traefik.httpRedirect" .Values.edge.traefik.httpRedirect
    "edge.traefik.createTlsOption" .Values.edge.traefik.createTlsOption -}}
{{- range $key := keys $flags | sortAlpha -}}
{{- if not (kindIs "bool" (get $flags $key)) -}}
{{- fail (printf "%s must be a boolean (true or false), got %q; a string value is not accepted" $key (toString (get $flags $key))) -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* True ("true") when the chart renders the Traefik edge TLS objects:
     the Ingress is on and the lab flag is off. */}}
{{- define "sbc.edgeTlsEnabled" -}}
{{- if and .Values.sbcClientConfig.enabled (not .Values.edge.insecureLabHttp) -}}true{{- end -}}
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

{{/* SR-41 announcement server mTLS. Secret with the announcement pod's
     server certificate (sbcAnnouncement.grpcMtls). */}}
{{- define "sbc.announcementServerTlsSecret" -}}
{{- .Values.sbcAnnouncement.grpcMtls.serverSecretName | default (printf "%s-announcement-server-tls" (include "sbc.fullname" .)) -}}
{{- end }}

{{/* Secret with the daemon's client certificate for the announcement pod. */}}
{{- define "sbc.announcementClientTlsSecret" -}}
{{- .Values.sbcAnnouncement.grpcMtls.daemonClientSecretName | default (printf "%s-announcement-client-tls" (include "sbc.fullname" .)) -}}
{{- end }}

{{/* SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES: the daemon client SAN by default. */}}
{{- define "sbc.announcementAllowedClientNames" -}}
{{- $names := .Values.sbcAnnouncement.grpcMtls.allowedClientNames | default (list (printf "%s-sbc-daemon" (include "sbc.fullname" .))) -}}
{{- join "," $names -}}
{{- end }}

{{/* In-cluster URL of the AnnouncementService (always https: the pod
     refuses plaintext off loopback). */}}
{{- define "sbc.announcementUrl" -}}
{{- printf "https://%s-announcement.%s.svc.cluster.local:9095" (include "sbc.fullname" .) .Release.Namespace -}}
{{- end }}

{{/* Render-time checks for the announcement pod (included from
     23-sbc-announcement-server.yaml): mTLS is required, from the daemon
     gRPC issuer or named Secrets (NIST 800-53 Rev5: IA-3, SC-8, CM-7). */}}
{{- define "sbc.announcementPreflight" -}}
{{- if .Values.sbcAnnouncement.enabled -}}
{{- $m := .Values.sbcAnnouncement.grpcMtls -}}
{{- if not .Values.sbcDaemon.grpcMtls.enabled -}}
{{- fail "sbcAnnouncement.enabled requires sbcDaemon.grpcMtls.enabled: the announcement pod serves Play over mTLS only; see DEPLOYING.md \"Announcement server mTLS\"" -}}
{{- end -}}
{{- if not (or .Values.sbcDaemon.grpcMtls.clusterIssuer (and $m.serverSecretName $m.daemonClientSecretName)) -}}
{{- fail "sbcAnnouncement.enabled requires sbcDaemon.grpcMtls.clusterIssuer (cert-manager) or sbcAnnouncement.grpcMtls.serverSecretName and daemonClientSecretName; see DEPLOYING.md \"Announcement server mTLS\"" -}}
{{- end -}}
{{- end -}}
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
# public NAT IP: sbcDaemon.config.outside_external_ip, either the public IP
# itself (preferred) or "stun:<ip>:<port>" naming an operator-run STUN
# server (SR-33: no public default, no DNS; a later different answer is
# not applied unless transport.stun_accept_external_ip_change is set).
# Checked at render time by sbc.outsideExternalIpPreflight.
external_ip = {{ .Values.sbcDaemon.config.outside_external_ip | quote }}

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
max_connections_per_listener = {{ .Values.sbcDaemon.config.max_connections_per_listener | int64 }}
max_connections_total = {{ .Values.sbcDaemon.config.max_connections_total | int64 }}
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
{{- if .Values.sbcDaemon.dtlsTerminate.enabled }}
# Terminate DTLS-SRTP at the SBC (decrypt + re-encrypt per leg). The Go
# terminator sidecar owns the cert + drives the handshake over the socket below.
mode = "Terminate"
{{- end }}

[media.dtls]
fingerprint_hash = "Sha384"
{{- if .Values.sbcDaemon.dtlsTerminate.enabled }}
# Shared with the sidecar container via the /run/usg emptyDir: the daemon reads
# the fingerprint file at startup for the SDP a=fingerprint and opens the socket
# per terminated leg.
sidecar_socket = "/run/usg/dtls-terminator.sock"
fingerprint_file = "/run/usg/dtls-terminator.fp"
{{- end }}

[security]
curve = "P384"
min_tls_version = "1.3"
require_mtls = false
{{- if .Values.sbcDaemon.sipTls.secretName }}
# SIP-over-TLS server credentials (Secret {{ .Values.sbcDaemon.sipTls.secretName }})
tls_cert_path = "/etc/sbc/sip-tls/tls.crt"
tls_key_path = "/etc/sbc/sip-tls/tls.key"
{{- end }}
{{- if or .Values.sbcDaemon.trunkTls.caConfigMap .Values.sbcDaemon.trunkTls.caSecretName }}
# Trust anchors for TLS SIP trunks (never the client-issuing CA).
trunk_tls_ca_path = "/etc/sbc/trunk-ca/ca.pem"
{{- end }}
{{- if .Values.sbcDaemon.trunkTls.requireTlsTrunks }}
# NIST 800-53 Rev5: SC-8 — every trunk group is TLS-only (POA&M-48).
require_tls_trunks = true
{{- end }}
{{- if or .Values.sbcDaemon.trunkTls.crlConfigMap .Values.sbcDaemon.trunkTls.crlSecretName }}
# CRLs for trunk server certificates (SR-29; NIST 800-53 Rev5: IA-5(2)).
trunk_tls_crl_path = "/etc/sbc/trunk-crl"
{{- end }}
{{- if or .Values.sbcDaemon.trunkTls.crlConfigMap .Values.sbcDaemon.trunkTls.crlSecretName .Values.sbcDaemon.revocation.require }}

[security.revocation]
check_depth = {{ .Values.sbcDaemon.revocation.checkDepth | quote }}
server_unknown = {{ .Values.sbcDaemon.revocation.serverUnknown | quote }}
expired_crl = {{ .Values.sbcDaemon.revocation.expiredCrl | quote }}
require = {{ .Values.sbcDaemon.revocation.require }}
{{- end }}
{{- if or .Values.sbcDaemon.stirShaken.verificationEnabled .Values.sbcDaemon.stirShaken.signingEnabled }}

[stir_shaken]
verification_enabled = {{ .Values.sbcDaemon.stirShaken.verificationEnabled }}
signing_enabled = {{ .Values.sbcDaemon.stirShaken.signingEnabled }}
{{- if .Values.sbcDaemon.stirShaken.verificationEnabled }}

[stir_shaken.verification]
trust_anchors_path = "/etc/sbc/sti-cr/sti-cr.pem"
{{- end }}
{{- if .Values.sbcDaemon.stirShaken.signingEnabled }}

[stir_shaken.signing]
certificate_path = "/etc/sbc/sti/tls.crt"
private_key_path = "/etc/sbc/sti/tls.key"
certificate_url = {{ .Values.sbcDaemon.stirShaken.certificateUrl | quote }}
{{- end }}
{{- end }}

# No [monitoring] table: it is not implemented and the daemon rejects it
# at config load (POA&M-191; exporter work tracked as POA&M-195).

[grpc]
# gRPC admin API. Used by sbc-api-server (when sbcApi.enabled) to call
# TrunkSync / DialPlanSync / DidMappingSync after operator writes, and by
# sbc-trunk-agent to publish trunk status. Kept off 9090
# (sbcDaemon.config.metrics_listen, reserved for a future metrics exporter).
# `enabled` defaults to false in the schema, so it MUST be set true
# here or the gRPC server never starts and sbc-api's writes silently
# skip the SIP-router refresh step.
#
# With sbcDaemon.grpcMtls (the default) the listener is on the pod network
# and every RPC on every service needs an allow-listed client certificate.
# Without it the listener is loopback only (sbc.grpcListen): the daemon
# refuses a plaintext listener off loopback (NIST 800-53 Rev5: AC-3, IA-3,
# SC-7, SC-8).
enabled = true
listen_addr = {{ include "sbc.grpcListen" . | quote }}
enable_reflection = false
require_mtls = {{ .Values.sbcDaemon.grpcMtls.enabled }}
{{- if .Values.sbcDaemon.grpcMtls.enabled }}
tls_cert_path = "/etc/sbc/grpc-tls/tls.crt"
tls_key_path = "/etc/sbc/grpc-tls/tls.key"
tls_ca_path = "/etc/sbc/grpc-tls/ca.crt"
# Only these client certificate names (SAN DNS/URI or subject CN) may call
# the gRPC API; default is the chart's sbc-api client certificate CN, plus
# the trunk-agent CN when sbcTrunkAgent is enabled (NIST 800-53 Rev5: AC-3, IA-3).
allowed_client_names = {{ include "sbc.grpcAllowedClientNames" . }}
{{- end }}

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
external_tls_port = {{ .Values.sbcDaemon.topologyHiding.externalTlsPort | default 5061 }}
{{- if .Values.sbcDaemon.topologyHiding.internalNetworks }}
internal_networks = {{ .Values.sbcDaemon.topologyHiding.internalNetworks | toJson }}
{{- end }}
{{- if .Values.sbcDaemon.topologyHiding.internalDomains }}
internal_domains = {{ .Values.sbcDaemon.topologyHiding.internalDomains | toJson }}
{{- end }}
{{- end }}

# Audit records (uc-audit) go to stdout with tracing target `audit`, which the
# daemon log filter always admits, for collection by the cluster log
# pipeline. On this path they are tamper-evident only through the hash chain
# carried in each record; no chart-managed audit file is written
# (NIST 800-53 Rev5: AU-2, AU-9, AU-12).
[logging]
level = "info"
format = "json"
output = "stdout"
audit_enabled = true

# Call Detail Records (NIST 800-53 Rev5 AU-12). The directory is its own
# volume (sbcDaemon.cdr.persistence, mounted at cdr.directory) so a CDR
# burst cannot fill the user/config store on the data volume. Retention is
# sized to it: (retention_files + 1) * rotate_size_mb + (attempts_retention_files
# + 1) * attempts_rotate_size_mb <= the CDR volume (AU-4); retention_days is
# authoritative (AU-11).
# The daemon refuses to start if it cannot write here.
[cdr]
enabled = {{ .Values.sbcDaemon.cdr.enabled }}
directory = {{ .Values.sbcDaemon.cdr.directory | quote }}
format = {{ .Values.sbcDaemon.cdr.format | quote }}
rotate_size_mb = {{ .Values.sbcDaemon.cdr.rotateSizeMb }}
rotate_interval = {{ .Values.sbcDaemon.cdr.rotateInterval | quote }}
retention_days = {{ .Values.sbcDaemon.cdr.retentionDays }}
retention_files = {{ .Values.sbcDaemon.cdr.retentionFiles }}
separate_attempts = {{ .Values.sbcDaemon.cdr.separateAttempts }}
{{- if .Values.sbcDaemon.cdr.separateAttempts }}
attempts_rotate_size_mb = {{ .Values.sbcDaemon.cdr.attemptsRotateSizeMb }}
attempts_retention_days = {{ .Values.sbcDaemon.cdr.attemptsRetentionDays }}
attempts_retention_files = {{ .Values.sbcDaemon.cdr.attemptsRetentionFiles }}
{{- end }}
{{- end }}
