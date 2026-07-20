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
  (see §6): `kubernetes.io/tls` Secrets created before install.
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
| `sbcDaemon.config` | SIP tuning | `max_calls`, `max_registrations`, `media_mode`, `srtp_required`, listen addrs (`grpc_listen` must differ from `metrics_listen`) |
| `sbcDaemon.sipTls` | SIP-over-TLS | `secretName` of a `kubernetes.io/tls` Secret covering the registrar domain; empty = UDP/TCP only |
| `sbcDaemon.oidc` | REGISTER authz | RFC 8898 bearer-token REGISTER; requires an IdP (see `sbcClientConfig.oidc`) |
| `gateway` | Edge HTTPS | Opt-in Gateway API + cert-manager termination; needs the Gateway API CRDs + cert-manager |
| `sbcClientConfig.oidc` / `extraCaCert` | Soft-client OIDC | Set `issuer`/`clientId`/`audience`; supply `extraCaCert` when the IdP uses a private CA |

Store the file at `deploy/helm/sites/sbc/<site-id>/values.yaml` (see
[../sites/README.md](../sites/README.md) for the layout convention). Render these
from a CSV/YAML inventory + template for many sites — the only
per-site differences are `site.*` and `bgp.upstream.ip`.

---

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
| Client-config ingress cert | `sbcClientConfig.ingressHost` (defaults to `sbc.<fqdn_base>`) | `sbcClientConfig.ingressTlsSecretName` |

If the IdP uses a private CA, set `sbcClientConfig.extraCaCert` to the PEM block
so the pods trust its OIDC metadata/JWKS. Alternatively, enable `gateway` to let
cert-manager issue and terminate the edge certificate automatically.

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
| Daemon can't reach Postgres | `sbcPostgres.password` unset, or external `existingSecret` DSN wrong | Set a password (in-chart) or fix the `dsn` key in the referenced Secret |

---

## See also

- [BOOTSTRAP.md](BOOTSTRAP.md) — greenfield microk8s node → cluster bring-up (Cilium/BGP/ExternalDNS)
- [values.yaml](values.yaml) — the full, commented configuration surface
- [sites/sbc/oopl-001/values.yaml](../sites/sbc/oopl-001/values.yaml) — a real Model-B (GHCR / k3s / dual-stack) site
- `../central-config/` — the fleet-wide central configuration plane (pairs with `sbcConfigSync`)
