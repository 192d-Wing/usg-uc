# SBC Site Bootstrap — 184-site rollout playbook

This is the step-by-step to bring a fresh microk8s node from "OS just installed" to "SBC pod Ready + reachable via BGP from upstream router". Every step is per-site and idempotent.

The architecture is **FQDN-first**: clients reach the SBC by name (`sbc.<site>.usg.example.com`), which resolves (via ExternalDNS) to the SBC's stable SIP/API LoadBalancer VIP (`site.sbc_lb_ip`), advertised upstream by BGP.

DHCP for phones is **not** part of this chart — it is served by **usg-dora** (a DORA fork), deployed and configured separately. This playbook covers the SBC only.

## Prerequisites per site

| Item | Detail |
|---|---|
| Hardware | x86_64 host with single NIC, ≥4 vCPU, ≥8 GiB RAM |
| OS | Ubuntu 24.04+ (snap-capable) |
| Upstream router | Supports BGP, can peer with k8s node ASN 65001 |
| Site `/28` LB pool | Per-site reserved /28 for LoadBalancer Service IPs (SBC SIP/API VIP + future) |
| DNS infrastructure | A DNS provider ExternalDNS can write to (Route53, CoreDNS-RFC2136, Cloudflare, …) |
| Site FQDN base | Per-site subdomain you control, e.g. `kfk-001.usg.example.com` |
| Upstream BGP config | See [§ Upstream router config](#upstream-router-config) |

## Step 1 — Install microk8s

```bash
sudo snap install microk8s --classic --channel=1.34/stable
sudo usermod -a -G microk8s "$USER"
newgrp microk8s
microk8s status --wait-ready
microk8s enable dns helm3 community
```

## Step 2 — Replace Calico with Cilium

Microk8s ships with Calico+VXLAN. We need Cilium+BGP for the L3 single-IP model.

> **Known issue**: `microk8s enable cilium` fails on snap-context shell-outs (`snapctl stop`). Use direct helm install instead — same result without the snap wrapper.

```bash
# Add cilium helm repo (helm3 is provided by microk8s)
sudo microk8s helm3 repo add cilium https://helm.cilium.io/
sudo microk8s helm3 repo update

# Install Cilium 1.19.x. The cni.exclusive=false flag preserves any other
# CNI binaries already in the bin path (we don't strictly need this for
# fresh installs, but it's harmless).
sudo microk8s helm3 install cilium cilium/cilium --version 1.19.4 \
  --namespace kube-system \
  --set cni.confPath=/var/snap/microk8s/current/args/cni-network \
  --set cni.binPath=/var/snap/microk8s/current/opt/cni/bin \
  --set cni.exclusive=false \
  --set daemon.runPath=/var/snap/microk8s/current/var/run/cilium \
  --set operator.replicas=1 \
  --set ipam.mode=cluster-pool \
  --set ipam.operator.clusterPoolIPv4PodCIDRList[0]=10.2.0.0/16 \
  --set ipv4NativeRoutingCIDR=10.2.0.0/16 \
  --set routingMode=native \
  --set autoDirectNodeRoutes=true \
  --set kubeProxyReplacement=false \
  --set bgpControlPlane.enabled=true \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set cni.chainingMode=portmap   # required for hostPort (SBC SIP WAN ingress)

# Wait for cilium agent Ready
sudo microk8s kubectl rollout status ds/cilium -n kube-system --timeout=180s
```

### Remove Calico

Microk8s' bundled Calico is still running. Remove it cleanly:

```bash
# 1) Delete Calico DaemonSet + controllers
sudo microk8s kubectl delete daemonset/calico-node \
                              deployment/calico-kube-controllers \
                              -n kube-system

# 2) Move the old Calico CNI conflist aside so containerd ignores it
sudo mv /var/snap/microk8s/current/args/cni-network/10-calico.conflist \
        /var/snap/microk8s/current/args/cni-network/10-calico.conflist.disabled

# 3) Rotate any pods still on calico (10.1.x.x) IPs so they get cilium ones
sudo microk8s kubectl get pods -A -o wide | \
  awk '$7 ~ /^10\.1\./ {print "-n",$1,$2}' | \
  xargs -L1 sudo microk8s kubectl delete pod
```

Verify everything is on Cilium IPs (10.2.x.x):

```bash
sudo microk8s kubectl get pods -A -o wide | grep -v '10\.0\.\|10\.2\.'
# (expect: only host-network pods like cilium-agent/multus show 10.0.x.x;
#  no 10.1.x.x left)
```

## Step 3 — Install ExternalDNS (one-time per cluster)

The chart publishes the SBC's FQDN via standard `external-dns.alpha.kubernetes.io/hostname` annotations on its Services. ExternalDNS itself must be installed cluster-wide once. Pick the provider matching your existing DNS infrastructure (Route53, CoreDNS-RFC2136, Cloudflare, Akamai EdgeDNS, etc.).

Generic ExternalDNS install via the upstream chart:

```bash
sudo microk8s helm3 repo add external-dns https://kubernetes-sigs.github.io/external-dns/
sudo microk8s helm3 install external-dns external-dns/external-dns \
  --namespace kube-system \
  --set provider=<your-provider> \
  --set sources={service} \
  --set txtOwnerId=<unique-cluster-id> \
  --set domainFilters[0]=<your-domain>     # e.g. usg.example.com
```

Provider-specific args go in `--set <provider>.*` (see the [ExternalDNS docs](https://kubernetes-sigs.github.io/external-dns/) for your provider).

ExternalDNS watches Services with the `external-dns.alpha.kubernetes.io/hostname` annotation and creates A records pointing at the Service's endpoint IPs. The SBC chart uses **headless** Services for SIP/API so the A records point directly at pod IPs (no DNAT, source IP preserved for SIP peer authentication).

> **Without ExternalDNS** the chart still installs cleanly — the annotations are inert and clients won't be able to resolve the SBC by FQDN. You can also pre-create A records manually for static deployments.

## Step 4 — Per-site Helm values

Create `deploy/helm/sites/sbc/<site-id>/values.yaml` (see
[../sites/README.md](../sites/README.md) for the layout):

```yaml
site:
  name: <site-id>                       # e.g. kfk-001, lowercase + DNS-safe
  node: <k8s-node-hostname>             # e.g. k8-01
  fqdn_base: "<site-id>.usg.example.com"  # zone ExternalDNS writes into
  lb_pool_cidr: "10.50.<X>.0/28"        # site's LoadBalancer IP pool
  sbc_lb_ip: "10.50.<X>.10"             # stable LB IP for SBC SIP/API

bgp:
  install_cluster_config: true          # set false on second-and-later installs
  cluster_asn: 65001
  upstream:
    ip: "<upstream-router-ip>"          # e.g. 10.0.100.1
    asn: 65000

externalDns:
  enabled: true                         # adds DNS-publish annotations to Services

image:
  repository: sbc-daemon
  tag: local
  pullPolicy: Never
```

> DHCP (phone subnets, pools, relay/TFTP options) is configured in the
> **usg-dora** deployment, not here.

For 184 sites: render values from a CSV/YAML inventory + a template. Site differences are just `name`, `node`, `fqdn_base`, `lb_pool_cidr`, `sbc_lb_ip`, and `bgp.upstream.ip`.

## Step 5 — Build & import the SBC images

Images are built locally and imported into microk8s containerd. **Known issue**: Cilium's BPF programs attach to all veths, which breaks podman's normal build-time veth creation — use `--network=host` to skip podman's network namespace.

### sbc-daemon (required)

```bash
cd /path/to/usg-uc
sudo podman build --network=host -t localhost/usg-sbc-daemon:local -f Dockerfile .

sudo podman save --quiet localhost/usg-sbc-daemon:local | \
  sudo microk8s ctr image import -
sudo microk8s ctr image tag --force \
  localhost/usg-sbc-daemon:local docker.io/library/usg-sbc-daemon:local
```

### sbc-announcement-server (optional — enable with `sbcAnnouncement.enabled: true`)

Delegates announcement RTP playback ("number not in service", "all circuits
busy") to a dedicated pod. The daemon falls back to in-process when absent.

```bash
sudo podman build --network=host -t localhost/usg-sbc-announcement-server:local \
  -f crates/sbc/sbc-announcement-server/Dockerfile .

sudo podman save --quiet localhost/usg-sbc-announcement-server:local | \
  sudo microk8s ctr image import -
sudo microk8s ctr image tag --force \
  localhost/usg-sbc-announcement-server:local \
  docker.io/library/usg-sbc-announcement-server:local
```

Set `sbcAnnouncement.advertisedIp` in site values to the pod's public IP (must
be reachable by calling phones/carriers). Set `SBC_ANNOUNCEMENT_URL` on the
daemon (or add it to `sbcDaemon.extraEnv` once that field is wired) pointing at
the ClusterIP service `http://<release>-announcement.<namespace>.svc:9095`.

### sbc-trunk-agent (optional — enable with `sbcTrunkAgent.enabled: true`)

Runs carrier REGISTER and OPTIONS health loops outside the daemon. Deploy
exactly one replica — two agents would double-REGISTER to carriers. When
enabled, also set `SBC_TRUNK_SERVICES=external` on the daemon.

```bash
sudo podman build --network=host -t localhost/usg-sbc-trunk-agent:local \
  -f crates/sbc/sbc-trunk-agent/Dockerfile .

sudo podman save --quiet localhost/usg-sbc-trunk-agent:local | \
  sudo microk8s ctr image import -
sudo microk8s ctr image tag --force \
  localhost/usg-sbc-trunk-agent:local \
  docker.io/library/usg-sbc-trunk-agent:local
```

For 184 sites: build once on a build host, push the OCI tarballs to each site's microk8s ctr.

## Step 6 — Deploy the chart

```bash
sudo microk8s helm3 install sbc-<site-id> deploy/helm/sbc \
  --namespace sbc-system --create-namespace \
  --values deploy/helm/sites/sbc/<site-id>/values.yaml
```

Verify:

```bash
# SBC pods Ready
sudo microk8s kubectl get pods -n sbc-system

# SBC SIP/API Service got its fixed LB IP from the site pool
sudo microk8s kubectl get svc -n sbc-system | grep sip
# expect: EXTERNAL-IP == sbc_lb_ip from values

# Cilium BGP advertising pod CIDR + the SBC SIP/API VIP /32
sudo microk8s kubectl exec -n kube-system ds/cilium -c cilium-agent -- \
  cilium bgp routes advertised

# DNS resolution working (if ExternalDNS wired up)
dig sbc.<site-id>.usg.example.com +short
```

## Upstream router config

One-time BGP peer config (FRR / Cumulus / SONiC syntax — Cisco IOS equivalent omits `no bgp ebgp-requires-policy`):

```
router bgp 65000
  bgp router-id <upstream-router-loopback>
  no bgp ebgp-requires-policy
  neighbor kube-nodes peer-group
  neighbor kube-nodes remote-as 65001
  neighbor kube-nodes soft-reconfiguration inbound
  neighbor <k8s-node-ip> peer-group kube-nodes
address-family ipv4 unicast
  neighbor kube-nodes activate
  neighbor kube-nodes default-originate
exit-address-family
```

Phone DHCP is handled by **usg-dora** (external to this chart). Per-VLAN
`ip helper-address` relay config points at the usg-dora relay target — see the
usg-dora deployment docs, not this playbook.

Verify the SBC's SIP/API VIP after install:
```bash
sudo microk8s kubectl -n sbc-system get svc | grep sip
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `sudo microk8s enable cilium` fails with `snapctl: cannot invoke...` | Known microk8s addon bug | Use direct `helm3 install` per Step 2 |
| `podman build` fails with `netavark: create veth pair: Netlink error` | Cilium BPF blocks default podman networking | Add `--network=host` to `podman build` |
| BGP session stays `Active`/`Idle` | BIRD not running — Calico's old `calico_backend: vxlan` still in ConfigMap | After Cilium install Calico's `calico-config` ConfigMap is irrelevant; if leftover Calico VXLAN routes persist on the node, `ip route flush` the affected /24 and restart |
| Pod stuck `ContainerCreating`, "no IP addresses available" | Stale CNI IPAM state from a previous Calico/whereabouts deployment | `sudo rm -rf /var/lib/cni/networks/*/10.0.*` |
| All pods on 10.1.x.x after install | Calico CNI conflist took priority | Verify `05-cilium.conflist` exists in `/var/snap/microk8s/current/args/cni-network/`; ensure `10-calico.conflist` is renamed `.disabled` |
| `helm install` rejects namespace adoption | Namespace exists but isn't Helm-owned | Run with `--create-namespace`; if it already exists, annotate it with Helm release metadata or delete + recreate |

## Site-by-site rollout checklist

For each of the 184 sites:

- [ ] Site /28 carved from the SBC supernet, recorded in inventory
- [ ] Upstream router BGP peer config added (3 lines)
- [ ] Phone DHCP handled by usg-dora (external) — VLAN `ip helper-address` points at its relay target
- [ ] microk8s installed + Cilium reinstall completed (Steps 1-2)
- [ ] `usg-sbc-daemon` image imported into local containerd (Step 5)
- [ ] (optional) `usg-sbc-announcement-server` image imported if using announcement pod
- [ ] (optional) `usg-sbc-trunk-agent` image imported if using trunk-agent pod
- [ ] `deploy/helm/sites/sbc/<site-id>/values.yaml` committed to inventory repo
- [ ] `helm install` completes successfully (Step 6)
- [ ] Upstream router shows pod CIDR via BGP (`show ip bgp <cidr>`)
- [ ] Test phone DHCPs successfully (from usg-dora)
- [ ] Test trunk REGISTER succeeds
