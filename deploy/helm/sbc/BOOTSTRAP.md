# SBC Site Bootstrap — 184-site rollout playbook

This is the step-by-step to bring a fresh microk8s node from "OS just installed" to "SBC pod Ready + reachable via BGP from upstream router". Every step is per-site and idempotent.

## Prerequisites per site

| Item | Detail |
|---|---|
| Hardware | x86_64 host with single NIC, ≥4 vCPU, ≥8 GiB RAM |
| OS | Ubuntu 24.04+ (snap-capable) |
| Upstream router | Supports BGP, can peer with k8s node ASN 65001 |
| Site /28 | Reserved per-site IPv4 CIDR not used elsewhere on the network |
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
  --set hubble.ui.enabled=true

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

## Step 3 — Per-site Helm values

Create `values-<site-id>.yaml`:

```yaml
site:
  name: <site-id>                  # e.g. kfk-001, lowercase + DNS-safe
  node: <k8s-node-hostname>        # e.g. k8-01
  pod_cidr: "10.50.<X>.0/28"       # this site's reserved /28
  sbc_ip: "10.50.<X>.10"           # informational only under cluster-pool
  kea_ip: "10.50.<X>.13"           # informational only under cluster-pool

bgp:
  install_cluster_config: true     # set false on second-and-later installs
  cluster_asn: 65001
  upstream:
    ip: "<upstream-router-ip>"     # e.g. 10.0.100.1
    asn: 65000

image:
  repository: sbc-daemon
  tag: local
  pullPolicy: Never

kea:
  phone_subnets:
    - subnet:      "<phone-vlan-cidr>"
      pool:        ["<dhcp-start>", "<dhcp-end>"]
      gateway:     "<phone-vlan-gateway>"
      tftp_server: "<sbc-ip>"      # = site.sbc_ip
```

For 184 sites: render values from a CSV/YAML inventory + a template. Site differences are just IPs/CIDRs/ASNs.

## Step 4 — Build & import the SBC image

The image is built locally and imported into microk8s containerd. **Known issue**: Cilium's BPF programs attach to all veths, which breaks podman's normal build-time veth creation — use `--network=host` to skip podman's network namespace.

```bash
cd /path/to/usg-uc
sudo podman build --network=host -t localhost/sbc-daemon:local -f Dockerfile .

# Import into microk8s containerd, tag for kubelet's bare-name lookup
sudo podman save --quiet localhost/sbc-daemon:local | \
  sudo microk8s ctr image import -
sudo microk8s ctr image tag --force \
  localhost/sbc-daemon:local docker.io/library/sbc-daemon:local
```

For 184 sites: build once on a build host, push the OCI tarball to each site's microk8s ctr.

## Step 5 — Deploy the chart

```bash
sudo microk8s helm3 install sbc-<site-id> deploy/helm/sbc \
  --namespace sbc-system --create-namespace \
  --values values-<site-id>.yaml
```

Verify:

```bash
# SBC + Kea pods Ready
sudo microk8s kubectl get pods -n sbc-system

# Cilium BGP advertising pod CIDR
sudo microk8s kubectl exec -n kube-system ds/cilium -c cilium-agent -- \
  cilium bgp routes advertised
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

Per phone VLAN (DHCP relay to Kea):

```
interface Vlan<phone-vlan-id>
  ip helper-address <kea-pod-ip>
```

Discover the Kea pod IP after `helm install`:
```bash
sudo microk8s kubectl -n sbc-system get pod \
  -l app.kubernetes.io/component=kea-dhcp4 \
  -o jsonpath='{.items[0].status.podIP}'
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
- [ ] Phone VLAN `ip helper-address` lines added (one per VLAN)
- [ ] microk8s installed + Cilium reinstall completed (Steps 1-2)
- [ ] SBC image imported into local containerd (Step 4)
- [ ] `values-<site-id>.yaml` committed to inventory repo
- [ ] `helm install` completes successfully (Step 5)
- [ ] Upstream router shows pod CIDR via BGP (`show ip bgp <cidr>`)
- [ ] Test phone DHCPs successfully from Kea
- [ ] Test trunk REGISTER succeeds
