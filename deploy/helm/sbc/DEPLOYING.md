# Deploying an SBC Site with Helm

How to deploy one USG SBC **site** with the `deploy/helm/sbc` chart: the per-site
values contract, the install/upgrade/rollback lifecycle, verification, and the
multi-site rollout pattern.

This guide is about the **chart**. For bringing a bare node up to a working
Kubernetes cluster (microk8s + Cilium/BGP + ExternalDNS), see
[BOOTSTRAP.md](BOOTSTRAP.md) — the greenfield node playbook. The two documents
compose: BOOTSTRAP gets you a cluster, this guide deploys the SBC onto it.

- Chart: `sbc` v0.8.0 (appVersion 0.8.0), `deploy/helm/sbc`
- Release name convention: `sbc-<site-id>` (e.g. `sbc-oopl-001`)
- Namespace: `sbc-system`

---

## 1. What a "site" is

A site is one SBC instance serving one physical location, deployed as a single
Helm release. The architecture is **FQDN-first and L3-routed**:

- The SBC pod gets a **dynamic** Cilium cluster-pool IP (changes on restart).
- Clients (phones, trunks, operators, soft clients) reach it by **name** —
  `sbc.<site.fqdn_base>` — published to DNS by ExternalDNS, or via a stable
  LoadBalancer VIP (`site.sbc_lb_ip`).
- The SBC SIP/API is reached at a **stable LoadBalancer VIP** (`site.sbc_lb_ip`)
  from a per-site pool, which the FQDN resolves to.
- **BGP** advertises the pod CIDR and the site's LoadBalancer pool upstream so
  those IPs are routable.
- **DHCP is out of scope for this chart** — phones get their addresses from
  **usg-dora** (a DORA fork), deployed and configured separately.

### What the chart deploys

| Component | Values key | Default | Role |
|-----------|-----------|---------|------|
| SBC daemon | `sbcDaemon` | on | SIP B2BUA / registrar / media relay (single replica per site) |
| Operator dashboard | `sbcFrontend` | on | React SPA + nginx; proxies `/api/*`, `/provision/*` |
| REST API | `sbcApi` | on | Config-entity CRUD out of Postgres; proxies the rest to the daemon |
| Provisioning | `sbcProvision` | on | Renders `/provision/<MAC>.{cfg,xml}` from Postgres |
| Client-config | `sbcClientConfig` | on | Soft-client discovery + OIDC `/v1/client-config` |
| Per-site Postgres | `sbcPostgres` | on | Config store (DIDs, phones, trunk groups, dial plans) |
| Announcement server | `sbcAnnouncement` | **off** | Dedicated announcement RTP playback pod |
| Trunk agent | `sbcTrunkAgent` | **off** | Carrier REGISTER + OPTIONS health loops (exactly 1 replica) |
| Config-sync | `sbcConfigSync` | **off** | Pulls this site's shard from the central config plane |
| Edge Gateway (TLS) | `gateway` | **off** | Gateway API + cert-manager HTTPS termination |

---

## 2. Pick a deployment model

Two supported models, distinguished almost entirely by **image source** and
which cluster-infra pieces the chart owns:

### Model A — Greenfield microk8s node (local images)

The 184-site rollout model. Images are **built locally** and imported into
microk8s containerd; the chart installs the cluster-wide BGP config on the first
site. This is what [BOOTSTRAP.md](BOOTSTRAP.md) walks through end to end.

```yaml
image:
  repository: localhost/usg-sbc-daemon
  tag: local
  pullPolicy: Never          # image is pre-imported; never pull
bgp:
  install_cluster_config: true   # first site on the cluster only
```

### Model B — Existing cluster, released images (GHCR)

Join an already-running cluster (e.g. k3s) using **published release images**
from GHCR. The cluster already has its own CNI/BGP/DNS, so the chart does not
create cluster BGP config and often disables ExternalDNS. See
[sites/sbc/oopl-001/values.yaml](../sites/sbc/oopl-001/values.yaml) for a real example.

```yaml
image:
  repository: ghcr.io/192d-wing/sbc-daemon
  tag: "0.8.0"
  pullPolicy: IfNotPresent
bgp:
  install_cluster_config: false      # cluster BGP already exists
  advertise_label: k3s-pod-cidrs     # match the existing CiliumBGPPeerConfig selector
externalDns: { enabled: false }
```

> Every component has its own `image:` block (`sbcFrontend.image`, `sbcApi.image`,
> …). In Model B, set each to the matching `ghcr.io/192d-wing/<component>:<tag>`
> — see [sites/sbc/oopl-001/values.yaml](../sites/sbc/oopl-001/values.yaml). In Model A they all default
> to `localhost/usg-*:local`.

---

## 3. Prerequisites

- A working cluster with **Cilium** (BGP control plane) — Model A: per
  [BOOTSTRAP.md](BOOTSTRAP.md); Model B: pre-existing.
- **Helm 3** (`microk8s helm3` on microk8s).
- The SBC **images** available to the node — imported into containerd (Model A)
  or pullable from GHCR (Model B).
- Per-site network facts recorded in your inventory:
  - Site ID (lowercase, DNS-safe), k8s node hostname, FQDN base
  - LoadBalancer pool CIDR + the SBC SIP/API VIP within it
  - Upstream router IP + ASN, cluster ASN
- **Out-of-band TLS certs** if terminating SIP-TLS / HTTPS with your own PKI
  (see §6): `kubernetes.io/tls` Secrets created before install. The
  dashboard ingress cert (`sbcClientConfig.ingressTlsSecretName`) is
  required: the chart does not render without it.
- **Traefik v3** as the ingress controller (the k3s-bundled one), with the
  `kubernetescrd` provider enabled (it serves the `traefik.io/v1alpha1`
  `TLSOption` and `Middleware` CRDs), a TLS entrypoint (`websecure`) and an
  HTTP entrypoint (`web`). Other entrypoint names go in `edge.traefik.*`.
  Without the CRDs, `helm install` fails with `no matches for kind
  "TLSOption"`; see "Upgrading to the edge TLS release" in §8.
- **The cluster default TLSOption set to the same profile.** Handshakes
  without SNI, or with an SNI that matches no router, use Traefik's
  `default` TLSOption (TLS 1.2 and Traefik's default suites unless changed),
  not the chart's. Create it once per cluster (only one TLSOption named
  `default` may exist), for example:

  ```yaml
  apiVersion: traefik.io/v1alpha1
  kind: TLSOption
  metadata:
    name: default
    namespace: kube-system        # the namespace Traefik runs in
  spec:
    minVersion: VersionTLS13
    maxVersion: VersionTLS13
    curvePreferences: [CurveP384]
    sniStrict: true
  ```
- One-time per cluster: **ExternalDNS** installed (Model A, if using FQDN
  publish) — see [BOOTSTRAP.md § Step 3](BOOTSTRAP.md).

---

## 4. Write the per-site values file

Create `deploy/helm/sites/sbc/<site-id>/values.yaml`. The minimal Model-A file:

```yaml
site:
  name: kfk-001                          # lowercase, DNS-safe; used in resource names
  node: k8-01                            # k8s node hostname for this site
  fqdn_base: "kfk-001.usg.example.com"   # zone ExternalDNS writes into
  lb_pool_cidr: "10.50.1.0/28"           # site's LoadBalancer IP pool (BGP-advertised)
  sbc_lb_ip:   "10.50.1.10"              # stable LB IP for SIP/API; sbc.<fqdn_base> resolves here
  # Optional dual-stack: leave both empty for v4-only.
  lb_pool_cidr6: ""
  sbc_lb_ip6:    ""

bgp:
  install_cluster_config: true           # true on the FIRST site per cluster, false after
  cluster_asn: 65001
  upstream:
    ip:  "10.0.100.1"                    # upstream router
    asn: 65000
  advertise_label: bgp                   # match existing config's selector when joining a cluster

externalDns:
  enabled: true                          # adds DNS-publish annotations to Services

image:
  repository: localhost/usg-sbc-daemon
  tag: local
  pullPolicy: Never

auth:
  create: true                           # generate the management-plane admin credential
  # adminPassword / adminPasswordHash optional; if both empty a random one is
  # generated and preserved in the <release>-auth Secret (retrieve it — see §7).

sbcPostgres:
  enabled: true
  password: "CHANGE-ME-STRONG"           # REQUIRED for production, or use existingSecret

sbcClientConfig:
  ingressTlsSecretName: sbc-kfk-001-ingress-tls   # REQUIRED: kubernetes.io/tls Secret (see §6)

sbcDaemon:
  config:
    max_calls: 5000
    max_registrations: 10000
    media_mode: Relay
    srtp_required: true

# DHCP is not part of this chart — phones are served by usg-dora (external).
```

### The values contract, block by block

| Block | Purpose | Notes |
|-------|---------|-------|
| `site` | Identity + IPs | `name`, `node`, `fqdn_base`, `lb_pool_cidr`, `sbc_lb_ip`; `*6` for IPv6 anycast |
| `bgp` | Upstream peering | `install_cluster_config: true` **only on the first site per cluster**; `advertise_label` must match the active `CiliumBGPPeerConfig` selector when joining |
| `externalDns` | FQDN publish | Annotations are always emitted; `enabled` just controls whether ExternalDNS acts on them |
| `image` + `<component>.image` | Image refs | Model A: `localhost/*:local` + `Never`; Model B: `ghcr.io/192d-wing/*:<tag>` + `IfNotPresent` |
| `auth` | Mgmt-plane admin | Fail-closed: `sbc-api`/`sbc-provision` won't start without a credential. Prefer `adminPasswordHash` (argon2 PHC) to keep plaintext out of values |
| `sbcPostgres` | Config store | `enabled: true` for the in-chart StatefulSet (set `password`), or `enabled: false` + `existingSecret.name` (key `dsn`) for managed Postgres |
| `sbcDaemon.config` | SIP tuning | `max_calls`, `max_registrations`, `max_connections_per_listener` / `max_connections_total` (stream connection caps, default 6000 / 8000; see "Sizing the connection caps" below), `media_mode`, `srtp_required`, listen addrs (`metrics_listen` is reserved and not rendered; the daemon rejects a `[monitoring]` table). The `-metrics` Service (`services.metrics`, port 9090) is off by default and has no listener behind it: no metrics exporter exists (POA&M-195) |
| `sbcDaemon.dtlsTerminate` | DTLS-SRTP termination (off by default) | `enabled` adds the Go DTLS sidecar to the daemon pod and sets `media.srtp.mode = Terminate`. `maxSessions` (`0` = 2 x `config.max_calls`) is the sidecar's session limit; `goMemLimit` (default `920MiB`) sets its `GOMEMLIMIT`; `resources.limits.memory` defaults to `1Gi`. Size the memory limit with `max_calls`: see "Upgrading to the client DTLS-SRTP release" in section 8 |
| `sbcDaemon.sipTls` | SIP-over-TLS | `secretName` of a `kubernetes.io/tls` Secret covering the registrar domain; empty = UDP/TCP only |
| `sbcDaemon.oidc` | REGISTER authz | RFC 8898 bearer-token REGISTER; requires an IdP (see `sbcClientConfig.oidc`) |
| `gateway` | Edge HTTPS | Opt-in Gateway API + cert-manager termination; needs the Gateway API CRDs + cert-manager |
| `edge` | Dashboard / login / client-config TLS on the Traefik Ingress | The router is pinned to `edge.traefik.entryPoint` (`websecure`) with the chart's `sbc-<site-id>-cnsa` TLSOption (TLS 1.3, P-384) and an HSTS middleware. `httpRedirect` (default `true`) adds a redirect-only router on `httpEntryPoint` (`web`). `createTlsOption: false` + `tlsOption: "<ns>-<name>@kubernetescrd"` uses your own TLSOption. `allowHttpProvisioning` (default `false`) serves `/provision/` only over HTTP for legacy phones. `insecureLabHttp` is lab only. See "Upgrading to the edge TLS release" in §8 |
| `sbcClientConfig.oidc` / `extraCaCert` | Soft-client OIDC | Set `issuer`/`clientId`/`audience`; supply `extraCaCert` when the IdP uses a private CA |

Store the file at `deploy/helm/sites/sbc/<site-id>/values.yaml` (see
[../sites/README.md](../sites/README.md) for the layout convention). Render these
from a CSV/YAML inventory + template for many sites — the only
per-site differences are `site.*` and `bgp.upstream.ip`.

---

### Sizing the connection caps

`sbcDaemon.config.max_connections_per_listener` and `max_connections_total`
are rendered into `[transport]`. Budget 128 KiB per TLS connection in the
worst case (a 4 KiB read chunk, a 64 KiB message buffer, about 40 KiB of TLS
state and the task) and keep connections under half of the daemon's
`resources.limits.memory`:

```text
max_connections_total <= memory limit / 2 / 128 KiB
```

The 2Gi default gives 8000 x 128 KiB = 1 GiB. Raise both caps only with the
memory limit. Keep the other half free: the pod's cgroup (v2) memory limit
also charges kernel socket buffers, which this budget does not count.

WebSocket connections (`ws_listen`, `wss_listen`) hold more in the worst
case, because tungstenite buffers do not shrink after a maximum-size
message:

```text
WS:  64 KiB in-buffer + 2 x 64 KiB out-buffer cap + 64 KiB message buffer = 256 KiB
WSS: 256 KiB + ~40 KiB TLS state                                          ~ 300 KiB
```

Size WebSocket deployments at 256 KiB (WS) or 300 KiB (WSS) per connection
(`max_connections_total <= memory limit / 2 / 300 KiB` for WSS).

At startup the daemon raises its soft `RLIMIT_NOFILE` to the hard limit and
checks that its fds fit:

```text
max_connections_total + 1024 egress + (rtp_port_max - rtp_port_min + 1)
  + SIP listeners + 256 REST HTTPS connections + 512 headroom <= RLIMIT_NOFILE
```

The RTP term is zero with an out-of-process media plane. If they do not fit,
it lowers the caps to fit, logs an error and records a configuration-change
audit event. It refuses to start when fewer than 64 connections would fit.

### SIP user HA1 encryption key (`sbcApi.ha1Key`)

sbc-api seals every SIP digest HA1 in the `users` table with AES-256-GCM and
**will not start without the key** (`SBC_USER_HA1_KEY_FILE`). The chart
requires `sbcApi.ha1Key.existingSecret`; rendering fails without it. Create
the Secret out-of-band (or via sealed-secrets / SOPS / Vault):

```bash
openssl rand -hex 32 | tr -d '\n' > ha1-key
kubectl -n <ns> create secret generic <name> --from-file=ha1-key=ha1-key
shred -u ha1-key
# values: sbcApi.ha1Key.existingSecret: <name>
```

**Lab only:** `sbcApi.ha1Key.generate: true` makes the chart generate the
key once into `<fullname>-ha1-key` (kept across upgrades and on uninstall via
`helm.sh/resource-policy: keep`). Do not use it with `helm template`,
`--dry-run`, Argo CD or Flux: `lookup` is empty there, so a render would emit
a new key and orphan every stored HA1. The key also ends up in Helm release
records. On `helm upgrade` the chart fails rather than regenerate if the
existing Secret cannot be read.

An init container copies the key into a memory-backed volume owned by the
pod uid with mode 0400 (the server rejects group/other-readable or
foreign-owned key files). On first start of this version, sbc-api encrypts
any existing plaintext HA1 rows before it begins serving (serialized across
replicas with a Postgres advisory lock). **Back the key up with the
database**: a database restore without its key leaves every SIP user unable
to authenticate until their passwords are re-provisioned. Key rotation is
not supported yet (POA&M-111).

## 5. Install

```bash
# Model A (microk8s)
sudo microk8s helm3 install sbc-<site-id> deploy/helm/sbc \
  --namespace sbc-system --create-namespace \
  --values deploy/helm/sites/sbc/<site-id>/values.yaml

# Model B (standard helm on an existing cluster)
helm install sbc-<site-id> deploy/helm/sbc \
  --namespace sbc-system --create-namespace \
  --values deploy/helm/sites/sbc/<site-id>/values.yaml
```

Dry-run / template first to inspect the rendered manifests:

```bash
helm template sbc-<site-id> deploy/helm/sbc --values deploy/helm/sites/sbc/<site-id>/values.yaml | less
helm install ... --dry-run --debug
```

> **First site per cluster:** ensure `bgp.install_cluster_config: true` so the
> cluster-wide `CiliumBGPClusterConfig` is created. **Every later site** on the
> same cluster must set it to `false` (otherwise the second install collides on
> the cluster-scoped resource).

---

## 6. Certificates (when using your own PKI)

The chart references TLS Secrets by name but does **not** create them — issue
them out-of-band and create the `kubernetes.io/tls` Secrets in `sbc-system`
before install:

| Secret referenced by | Covers | Values key |
|----------------------|--------|-----------|
| SIP-over-TLS server cert | registrar domain (`sbcClientConfig.registrarDomain`) | `sbcDaemon.sipTls.secretName` |
| Dashboard / client-config ingress cert (**required**; ECDSA P-384 key, SHA-384 signature for CNSA 2.0) | `sbcClientConfig.ingressHost` (defaults to `sbc.<fqdn_base>`) | `sbcClientConfig.ingressTlsSecretName` |

If the IdP uses a private CA, set `sbcClientConfig.extraCaCert` to the PEM block
so the pods trust its OIDC metadata/JWKS. Alternatively, enable `gateway` to let
cert-manager issue and terminate the edge certificate automatically.

### Daemon gRPC mTLS

`sbcDaemon.grpcMtls.enabled` is `true` by default: sbc-api and the trunk agent
reach the daemon gRPC (port 9091) over the pod network, and the daemon refuses
a plaintext gRPC listener that is not on loopback. Rendering fails until you
supply one of:

- **cert-manager:** `sbcDaemon.grpcMtls.clusterIssuer: <issuer>` (and
  `issuerKind: Issuer` for a namespaced issuer). The chart issues ECDSA P-384
  certificates: the server certificate for `<fullname>-grpc`, the sbc-api
  client certificate (CN `<fullname>-sbc-api`) and, with
  `sbcTrunkAgent.enabled`, the trunk-agent client certificate (CN
  `<fullname>-sbc-trunk-agent`). Use a dedicated CA issuer for this, for
  example a namespaced CA `Issuer`:

  ```yaml
  apiVersion: cert-manager.io/v1
  kind: Issuer
  metadata: { name: sbc-grpc-ca, namespace: sbc-system }
  spec:
    ca: { secretName: sbc-grpc-ca }   # tls.crt/tls.key of a P-384 CA
  ```

  A shared `ClusterIssuer` also works, but then any workload that can request
  a certificate from it can obtain an allow-listed name.
- **Your own Secrets:** `serverSecretName` and `clientSecretName` (plus
  `trunkAgentClientSecretName` with the trunk agent), each holding `tls.crt`,
  `tls.key` and `ca.crt`. P-384 example with `openssl`:

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 365 \
    -subj "/CN=sbc-grpc-ca" -keyout ca.key -out ca.crt
  F=sbc-<site>   # the chart fullname
  issue() { # $1 name, $2 extension
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
      -subj "/CN=$1" -keyout "$1.key" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -days 90 \
      -extfile <(printf '%s' "$2") -out "$1.crt"
    kubectl -n sbc-system create secret generic "$1-tls" \
      --from-file=tls.crt="$1.crt" --from-file=tls.key="$1.key" --from-file=ca.crt
  }
  issue "$F-grpc" "subjectAltName=DNS:$F-grpc,DNS:$F-grpc.sbc-system.svc,DNS:$F-grpc.sbc-system.svc.cluster.local
  extendedKeyUsage=serverAuth"
  issue "$F-sbc-api" "extendedKeyUsage=clientAuth"
  issue "$F-sbc-trunk-agent" "extendedKeyUsage=clientAuth"   # with the trunk agent
  ```

  then set `serverSecretName: $F-grpc-tls`, `clientSecretName: $F-sbc-api-tls`
  and `trunkAgentClientSecretName: $F-sbc-trunk-agent-tls`.

`grpcMtls.enabled: false` renders only with `sbcApi.enabled: false` and
`sbcTrunkAgent.enabled: false`: the daemon gRPC then listens on 127.0.0.1 only
(no `-grpc` Service), reachable from inside the pod, e.g. `kubectl exec ...
sbc-cli`.

---

## 7. Verify

Post-install (`helm ... NOTES` prints a site-specific version of this):

```bash
NS=sbc-system; REL=sbc-<site-id>

# Pods + services for this release Ready
kubectl -n $NS get pods,svc -l app.kubernetes.io/instance=$REL

# SBC SIP/API Service holds its fixed LB IP from the site pool
kubectl -n $NS get svc | grep sip            # EXTERNAL-IP == site.sbc_lb_ip

# Cilium advertising the pod CIDR + LB pool upstream
kubectl exec -n kube-system ds/cilium -c cilium-agent -- cilium bgp routes advertised

# FQDN resolves (if ExternalDNS wired up)
dig sbc.<fqdn_base> +short          # e.g. sbc.kfk-001.usg.example.com
```

On the upstream router:

```bash
show ip bgp summary
show ip bgp <site.sbc_lb_ip>/32
ping <site.sbc_lb_ip>
```

Retrieve the generated admin password (when `auth` generated one):

```bash
kubectl -n $NS get secret ${REL}-auth -o jsonpath='{.data.admin-password}' | base64 -d ; echo
```

Log in to the management plane:

```bash
curl -k https://sbc.<fqdn_base>/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<password>"}'
# then send: Authorization: Bearer <token>
```

---

## 8. Upgrade, rollback, uninstall

```bash
# Upgrade (e.g. bump image tags or tune config) — edit the values file, then:
helm upgrade sbc-<site-id> deploy/helm/sbc -n sbc-system --values deploy/helm/sites/sbc/<site-id>/values.yaml

# Watch the rollout
kubectl -n sbc-system rollout status deploy/sbc-<site-id>-frontend

# Roll back to the previous revision if an upgrade misbehaves
helm history sbc-<site-id> -n sbc-system
helm rollback sbc-<site-id> <REVISION> -n sbc-system

# Uninstall (keeps PVCs by default — see note)
helm uninstall sbc-<site-id> -n sbc-system
```

> **Data safety:** the daemon PVC (`/var/lib/sbc`) and the Postgres PVC survive
> pod restarts, `helm upgrade`, and node reboots. `helm uninstall` does **not**
> delete PVCs — remove them explicitly (`kubectl -n sbc-system delete pvc -l
> app.kubernetes.io/instance=sbc-<site-id>`) only when you intend to discard the
> site's config/registration state. The SBC daemon runs a single replica per
> site (`ReadWriteOnce`); upgrades are a brief restart, not a rolling handover.

### Upgrading to the management-API hardening release (fix/mgmt-api-hardening)

This upgrade has breaking changes. Check each point before you upgrade.

- **Everyone must log in again.** Management API tokens are now `v2.`
  (HMAC-SHA-384, with `aud` and `iat` claims). `v1.` tokens are rejected and
  there is no fallback.
- **`SBC_AUTH_SIGNING_KEY`** must be hex and decode to at least 32 bytes; 48
  bytes is recommended (`openssl rand -hex 48`). A key that is set but empty,
  is not hex, or is shorter than 32 bytes stops startup. Keys of 32 to 47 bytes
  load with a warning. The chart generates a 48-byte key for new installs and
  keeps an existing key on upgrade.
- **`SBC_AUTH_TOKEN_TTL_SECS`** must be between 60 and 86400. Values outside
  that range stop startup.
- **`SBC_PROVISION_SECRET`** (only if set) must be hex and decode to at least
  32 bytes (`openssl rand -hex 48`). Provisioning tokens are now HMAC-SHA-384,
  so old 64-character `?token=` values return 403. Re-mint every phone's
  provisioning URL token with `sbc-provision-server --mint-token <MAC>` (reads
  `SBC_PROVISION_SECRET`, prints the token, exits 2 on error). Deployments that
  use only CIDR allow-lists are not affected.
- **Daemon REST API over HTTPS** is now TLS 1.3 only with the CNSA suite set,
  whatever `security.min_tls_version` says. The key must match
  `security.curve`, or the daemon will not start. It serves HTTP/1.1 only (no
  HTTP/2) and limits connections: 256 concurrent, a 10 s handshake timeout, a
  10 s header-read/idle timeout, and a 300 s maximum connection age.
- **Certificate hot reload:** the daemon polls the REST API certificate and key
  files every 30 s and reloads them when they change, so cert-manager renewals
  apply without a restart. A failed reload keeps the old certificate in use;
  watch `sbc_api_tls_cert_reload_failures_total`.

### Upgrading to the containment hardening release (pr/sec-containment)

This upgrade has breaking changes. Check each point before you upgrade.

- **Daemon gRPC mTLS is on by default** (`sbcDaemon.grpcMtls.enabled: true`)
  and needs `grpcMtls.clusterIssuer` or explicit Secret names; rendering
  fails otherwise (see "Daemon gRPC mTLS" above). Site values files,
  including `deploy/helm/sites/sbc/oopl-001/values.yaml`, must add one.
  `grpcMtls.enabled: false` now fails rendering while `sbcApi` or
  `sbcTrunkAgent` is enabled. The trunk agent can now run with mTLS (its own
  client certificate, `grpcMtls.trunkAgentClientSecretName`).
- **`sbcDaemon.config.grpc_listen` defaults to empty**: `0.0.0.0:9091` with
  mTLS, `127.0.0.1:9091` without. A non-loopback value without mTLS fails
  rendering, and the daemon refuses such a `[grpc]` section at startup. The
  `-grpc` Service exists only with mTLS.
- **NetworkPolicies are on by default** (`networkPolicy.enabled: true`,
  `templates/28-sbc-networkpolicy.yaml`): default-deny ingress for every pod
  of the release, with allows for SIP/RTP to the daemon, daemon REST from the
  frontend and sbc-api, daemon gRPC from sbc-api and the trunk agent, sbc-api
  and provisioning from the frontend, the frontend and client-config from
  `networkPolicy.edgeFrom` (any source when empty) and Postgres from the
  release pods. Any other caller (Prometheus scrapes, ad-hoc tools) is
  blocked: add it with `networkPolicy.daemonGrpcFrom` (gRPC) or turn the
  policies off. On CNIs that enforce policy on host traffic, set
  `networkPolicy.probeFrom` to the node CIDR. Needs Kubernetes >= 1.25.
- **sbc-media (mediaSplit) binds its controller to 127.0.0.1:9096**; a
### Upgrading to the edge TLS release (SR-53)

This upgrade has breaking changes. The dashboard, `/api/v1/auth/login` and
`/v1/client-config` are now served over TLS only. Check each point before you
upgrade.

- **A TLS secret is required.** With `sbcClientConfig.enabled` (the default),
  the chart fails to render unless `sbcClientConfig.ingressTlsSecretName`
  names a `kubernetes.io/tls` Secret for the ingress host. Issue an ECDSA
  P-384 leaf signed with SHA-384 (§6). This applies even with
  `sbcFrontend.enabled: false`, because the client-config route carries
  bearer tokens.
- **No cleartext LoadBalancer for the dashboard.** With neither
  `gateway.enabled` nor `sbcClientConfig.enabled`, the frontend used to be a
  LoadBalancer on port 80. That now fails to render. Enable one of the two
  edges.
- **Traefik router.** The Ingress is bound to `edge.traefik.entryPoint`
  (`websecure`) only, with `router.tls`, the TLSOption
  `<namespace>-sbc-<site-id>-cnsa@kubernetescrd` and the HSTS middleware
  `<namespace>-sbc-<site-id>-hsts@kubernetescrd` (one year, `includeSubDomains`,
  no preload). Plain HTTP on `edge.traefik.httpEntryPoint` (`web`) gets a
  301 to https from a redirect-only router (`sbc-<site-id>-client-config-redirect`).
  With `edge.traefik.httpRedirect: false` there is no router on `web` for
  this host, and Traefik answers 404.
- **TLSOption `sbc-<site-id>-cnsa`.** It allows TLS 1.3 only, with the P-384
  group only and `sniStrict`. Clients that offer only X25519 or a hybrid
  ML-KEM group fail the handshake, as do TLS 1.2 clients. Go's TLS stack
  does not allow TLS 1.3 cipher suites to be restricted, so a client that
  prefers AES-128-GCM or ChaCha20 still gets it (POA&M-436). `sniStrict`
  applies to handshakes that reach this TLSOption. Handshakes without SNI
  use the cluster's `default` TLSOption; set it to the same profile (§3).
- **Clusters with a central TLS policy**:
  set `edge.traefik.createTlsOption: false` and
  `edge.traefik.tlsOption: "<namespace>-<name>@kubernetescrd"` naming an
  equivalent TLSOption. The chart fails if the ref is empty or names the
  cluster `default` TLSOption (`default`, `default@<provider>`). The edge
  TLS profile then depends on that object (operator-asserted). The HSTS and redirect middlewares are
  still `traefik.io/v1alpha1` objects, so the `kubernetescrd` provider is
  still required.
- **Value checks.** The four `edge` flags (`insecureLabHttp`,
  `traefik.httpRedirect`, `traefik.createTlsOption`,
  `traefik.allowHttpProvisioning`) must be YAML booleans: a quoted `"false"`
  fails the render (it would otherwise count as true). Tools that force
  strings (`--set-string`, Argo CD `forceString`, Flux `valuesFrom`
  targetPath) must pass these as booleans. `edge.traefik.hsts.maxAgeSeconds`
  must be at least 31536000. `entryPoint` and `httpEntryPoint` must differ
  while the redirect or provisioning router is on.
- **Entrypoint names.** If your Traefik entrypoints are not called
  `websecure` and `web`, set `edge.traefik.entryPoint` and
  `edge.traefik.httpEntryPoint`. A wrong name leaves the dashboard
  unreachable: it does not fall back to HTTP.
- **Phones that provision over plain HTTP.** `http://sbc.<site>/provision/...`
  now gets a 301 to https. Phones that cannot follow it to HTTPS stop
  provisioning. Point them at the `https://` URL. As a legacy exception,
  `edge.traefik.allowHttpProvisioning: true` adds an HTTP router for
  `/provision/` only (`sbc-<site-id>-provision-http`, through the frontend
  nginx; requires `sbcFrontend.enabled`). A marker header set by that
  router makes the frontend nginx answer 403 for anything outside
  `/provision/`, after nginx's own path normalisation, so the dashboard and
  `/api` cannot be reached over HTTP whatever the Traefik version. On that
  router, the device's provisioning token (`?token=`, static per device,
  POA&M-120) and the provisioning documents, which carry the phone's SIP
  digest password and any LDAP bind password, cross the network in
  cleartext. A captured token can be replayed to fetch the document again
  (POA&M-437). Use it only on an isolated phone VLAN, for as short a time
  as possible. After turning it off, rotate `SBC_PROVISION_SECRET`
  (re-mint every phone's token with `sbc-provision-server --mint-token`)
  and the SIP credentials (and LDAP bind passwords) of every phone that
  provisioned over HTTP.
- **Lab only: `edge.insecureLabHttp: true`.** This restores the old
  behaviour: no TLS requirement, no entrypoint pin, no TLSOption, no HSTS,
  and a cleartext frontend LoadBalancer when there is no edge. Passwords and
  tokens then cross the network unencrypted. `helm install`/`upgrade`
  prints a warning. Never set it outside a lab.
- **Gateway path** (`gateway.enabled`). HTTPS with a cert-manager
  certificate and an HTTP to HTTPS redirect, as before. The Certificate now
  requests an ECDSA P-384 key with `rotationPolicy: Always`, so cert-manager
  re-issues an existing RSA certificate on upgrade. Use an issuer that signs
  with SHA-384. The Gateway API has no TLS version or suite control
  (POA&M-437).
- **Bundled Postgres** still defaults to `sslmode: disable` (POA&M-384). That
  is separate from this change.

Check after the upgrade:

```bash
kubectl -n sbc-system get tlsoption,middleware.traefik.io -l app.kubernetes.io/instance=sbc-<site-id>
curl -sI http://sbc.<fqdn_base>/ | head -1                 # 301 (or 404 with httpRedirect: false)
curl -sI https://sbc.<fqdn_base>/ | grep -i strict-transport-security
openssl s_client -connect sbc.<fqdn_base>:443 -servername sbc.<fqdn_base> -tls1_2 </dev/null   # handshake failure
```

  non-loopback `SBC_MEDIA_GRPC_LISTEN` exits with code 2 unless mTLS
  (`SBC_MEDIA_GRPC_TLS_*` plus `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES`) is
  configured. The chart's co-located pod keeps loopback.
- **`X-Real-IP` is ignored unless `SBC_TRUSTED_PROXIES` is set.** Set
  `sbcProvision.trustedProxies` (required with `allowedSourceCidrs`; rendering
  fails otherwise) and `sbcApi.trustedProxies` to the frontend pod CIDR. A
  pod-CIDR value is sound only while `networkPolicy.enabled` (on a CNI that
  enforces it): with policies off, rendering fails unless you set
  `networkPolicy.trustedProxiesWithoutPolicy: true` and restrict access to
  sbc-api and provisioning some other way. For phone addresses to reach nginx
  through an ingress controller, also set `sbcFrontend.realIpFrom` to the
  edge proxies' **own** addresses only (never the whole pod CIDR: every listed
  address may assert any client address), together with
  `networkPolicy.edgeFrom` naming those proxies (rendering fails without it
  while policies are on), so nothing else can reach the frontend.
  Admin password logins are limited to 5 failures per client IP (IPv6: per
  /64) and 10 in total per 15 min window, per sbc-api replica; without
  `sbcApi.trustedProxies` all clients behind nginx share one IP bucket. A
  lock ends with its window. OIDC and API keys are not affected.
- **`SBC_PROVISION_SECRET`** can now come from a Secret:
  `sbcProvision.provisionSecret.existingSecret` (key
  `sbcProvision.provisionSecret.key`, default `provision-secret`).
- **OIDC access to sbc-api needs realm role `fleet-admin` and `sites` ∋ `*`**;
  other valid tokens get 403. The `config-admin` scope no longer grants
  anything on its own (central-config-api as well). See
  `deploy/keycloak/central-config-clients.md`.
- **central-config chart: no default database password.** `postgres.password`
  (bundled) and `postgres.cnpg.password` (cnpg, or
  `postgres.cnpg.existingSecret`) are required, and `change-me` is refused.
  On an existing install set the password the database already uses, or
  rotate the role password in the database in the same change: a new Secret
  value alone does not change the password of an initialised bundled
  Postgres. In cnpg mode the chart-owned DSNs now use `sslmode=verify-full`
  against `postgres.cnpg.caSecret` (default `<cluster>-ca`, key `ca.crt`).

### Upgrading to the client DTLS-SRTP release (feat/client-dtls-wiring)

Applies only to sites with `sbcDaemon.dtlsTerminate.enabled: true`. The
figures below come from local runs on macOS; nothing here has been measured
or run on Linux yet (NIST POA&M-339, POA&M-342). Details and the log records
are in [docs/SBC-ADMIN-GUIDE.md](../../../docs/SBC-ADMIN-GUIDE.md), "DTLS
sidecar operation".

- **Upgrade the SBC (and with it the sidecar image) before any soft client
  that performs DTLS-SRTP.** The older sidecar sent `close_notify` right
  after the handshake; such a soft client then ends every call after about
  one second (`media-security: dtls-closed-by-peer`). Set
  `sbcDaemon.dtlsTerminate.image.tag` to the sidecar image built from this
  release in the same upgrade as the daemon image.
- **The sidecar now holds each call's DTLS association for the whole call.**
  Restarting the sidecar container (on purpose, by its liveness probe, or by
  an out-of-memory kill) ends the DTLS association of every call in
  progress. The SBC keeps relaying media on those calls and does not end
  them; a peer that honours `close_notify` (the soft client does) ends its
  side. Drain first: restart the sidecar only when no terminated call is up.
  A `helm upgrade` restarts the whole daemon pod, as before.
- **New values under `sbcDaemon.dtlsTerminate`:**
  - `maxSessions` (default `0`): the sidecar's `-max-sessions`. `0` renders
    2 x `sbcDaemon.config.max_calls` (two sessions per terminated call). At
    the limit a new call fails to set up; calls in progress are not touched.
  - `goMemLimit` (default `"920MiB"`): `GOMEMLIMIT` for the sidecar, about
    90 % of `resources.limits.memory`. Empty leaves the variable unset.
- **Sidecar memory default raised:** limit `256Mi` -> `1Gi`, request `64Mi`
  -> `128Mi`. A site values file that overrides
  `sbcDaemon.dtlsTerminate.resources` keeps its own numbers: check them
  against the formula.
- **Sizing formula:** memory limit >= `16 MiB + max_calls x 150 KiB`, plus
  headroom for the Go collector; `goMemLimit` about 90 % of the limit.
  `max_calls: 5000` gives 749 MiB, hence `1Gi` / `920MiB`. `max_calls: 10000`
  gives about 1.5 GiB: use `2Gi` / `1840MiB`. If you raise `max_calls`,
  raise both. Caveats:
  - 150 KiB per call was measured once, on macOS arm64; the 16 MiB base is
    assumed. **Measure the sidecar's resident memory on Linux at your
    `max_calls` before enabling termination at scale.**
  - Not included: up to about 64 KiB per session that a session's own peer
    can pin with unauthenticated handshake datagrams after the handshake.
    For hostile peers size with `16 MiB + max_calls x 278 KiB`.
  - If the limit is hit, the kernel kills the sidecar and every call loses
    its DTLS association at once.
- **New SBC log record `dtls.association.closed`** (one per terminated leg,
  with `call_id`, `leg`, `remote`, `reason`): info for `call-ended`, warn
  for `peer-close-notify`, `peer-fatal-alert`, `sidecar-shutdown`,
  `sidecar-connection-lost`, `sidecar-close-timeout`, `sidecar-error`. A
  sidecar restart with N terminated calls up writes 2N warnings. The
  `close_notify` / fatal-alert distinction is inferred by the sidecar and is
  advisory.
- **Post-handshake DTLS is rate limited** on each terminated leg (burst 8,
  then 4 per second); drops are counted and logged with the call id.
- **Session count:** the sidecar logs
  `sessions: active=N peak=N max=N refused=N` once a minute while it has
  sessions. There is no metric for it.

### Upgrading to the data-plane wiring release (pr/data-plane-wiring-b403f0)

Applies only to daemons built with the `cluster` feature that set `[cluster]`
or `[storage]` in `config.toml`. The chart renders neither section.

- **Shared storage must use TLS.** Startup fails unless PostgreSQL uses
  `ssl_mode = "verify_full"` (or `verify_ca`) and Redis uses a `rediss://` URL.
  To keep a non-TLS backend, set `allow_insecure_transport = true` in the
  backend table; the daemon logs a `storage.insecure_transport_allowed`
  warning.
- **`cluster.enabled = true` requires `[cluster.auth]`** with `key_file` (at
  least 48 random bytes, mode 0600; group/other-readable files are refused)
  and `key_id`. Startup aborts if the key is missing or unreadable. No peer
  transport exists yet, so the key does not yet protect any traffic.

---

## 9. Multi-site rollout

For a fleet, treat each site as `deploy/helm/sites/sbc/<site-id>/values.yaml`
committed to an inventory repo and rendered from a template. Per-site checklist
(condensed from
[BOOTSTRAP.md](BOOTSTRAP.md#site-by-site-rollout-checklist)):

- [ ] Site `/28` (or `/31`) carved from the LB supernet, recorded in inventory
- [ ] Upstream router BGP peer added
- [ ] Cluster ready (Model A: microk8s + Cilium per BOOTSTRAP; Model B: existing)
- [ ] Images available on the node (imported for A, pullable for B)
- [ ] `deploy/helm/sites/sbc/<site-id>/values.yaml` committed — remember `bgp.install_cluster_config`
      is `true` for the first site on a cluster, `false` afterwards
- [ ] `helm install` succeeds; pods Ready
- [ ] Upstream router shows the pod CIDR + SBC SIP/API VIP `/32` via BGP
- [ ] DHCP served by usg-dora (external); test trunk REGISTER succeeds

---

## 10. Troubleshooting

Chart/site-level pointers; the cluster bring-up gotchas (Cilium replacing Calico,
podman `--network=host`, stale CNI IPAM) live in
[BOOTSTRAP.md § Troubleshooting](BOOTSTRAP.md#troubleshooting).

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Second site's install fails on a cluster-scoped BGP resource | `bgp.install_cluster_config: true` on a non-first site | Set it to `false`; only the first site owns the cluster BGP config |
| `sbc-api` / `sbc-provision` pod CrashLoopBackOff at startup | Fail-closed auth with no credential | Set `auth.create: true` (or `existingSecret`); confirm the `<release>-auth` Secret exists |
| SBC SIP Service has no / wrong `EXTERNAL-IP` | LB pool CIDR not advertised, or `sbc_lb_ip` outside `lb_pool_cidr` | Check `site.lb_pool_cidr`/`sbc_lb_ip`; verify the `CiliumLoadBalancerIPPool` and BGP advertisement |
| Phones don't resolve `sbc.<site>` | ExternalDNS disabled, or the DNS server usg-dora hands phones is wrong | Enable `externalDns` (or pre-create A records); fix the DNS option in the usg-dora scope |
| Soft client REGISTER hangs after DNS returns AAAA | `sbc_lb_ip6` published but not actually routed | Allocate + BGP-advertise a real v6 VIP, or clear `site.*6` for v4-only |
| SIP-TLS listener logs a warning and only UDP/TCP serve | `sbcDaemon.sipTls.secretName` empty or cert missing | Create the `kubernetes.io/tls` Secret covering the registrar domain and set the name |
| Soft-client calls through a terminating SBC drop about 1 s after answer with `media-security: dtls-closed-by-peer` | Sidecar image older than the client DTLS-SRTP release (it closes the DTLS association right after the handshake). Not reproduced on a deployed site; with this release's daemon the SBC log is expected, from the code, to show `dtls.association.closed` with `reason="sidecar-connection-lost"` shortly after setup | Upgrade `sbcDaemon.dtlsTerminate.image.tag` to this release |
| New terminated calls fail to set up; sidecar logs `session limit reached` | Sidecar at `-max-sessions` | Check `sbcDaemon.dtlsTerminate.maxSessions` against 2 x `config.max_calls`; look for leaked sessions in the once-a-minute `sessions:` line |
| Many `dtls.association.closed` warnings at once with `sidecar-shutdown` or `sidecar-connection-lost` | The sidecar container was restarted or killed (liveness probe, OOM kill) | Check the container's last state; if OOM-killed, resize the memory limit and `goMemLimit` with the formula in section 8 |
| Daemon can't reach Postgres | `sbcPostgres.password` unset, or external `existingSecret` DSN wrong | Set a password (in-chart) or fix the `dsn` key in the referenced Secret |

---

## See also

- [BOOTSTRAP.md](BOOTSTRAP.md) — greenfield microk8s node → cluster bring-up (Cilium/BGP/ExternalDNS)
- [values.yaml](values.yaml) — the full, commented configuration surface
- [sites/sbc/oopl-001/values.yaml](../sites/sbc/oopl-001/values.yaml) — a real Model-B (GHCR / k3s / dual-stack) site
- `../central-config/` — the fleet-wide central configuration plane (pairs with `sbcConfigSync`)
