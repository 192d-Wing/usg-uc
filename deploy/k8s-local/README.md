# Local Kind Cluster for the USG SBC

Spins up a single-node [kind](https://kind.sigs.k8s.io/) cluster with [Multus](https://github.com/k8snetworkplumbingwg/multus-cni) and [MetalLB](https://metallb.universe.tf/) so the SBC's three zone interfaces (inside / outside / oobm) can live directly on a physical LAN via macvlan.

**Linux only.** macOS isn't supported — Docker Desktop's VM can't attach a macvlan to a host NIC. Run this on a Linux host (bare metal or VM with a bridged interface).

## How it works

- The kind node is attached to a Docker `macvlan` network whose parent is a real host NIC (the "trunk").
- Inside the pod, Multus adds three macvlan child interfaces, one per zone. Each gets a static IP from the LAN subnet via `host-local` IPAM.
- Routable LAN access for SIP/RTP traffic; in-cluster Services + MetalLB for API/metrics discovery.

## Prerequisites

- `docker` (with the daemon running)
- `kind`
- `kubectl`
- `python3`
- `sudo` access for `ip link`, `iptables`, and the Docker `macvlan` driver
- A dedicated host NIC on the cluster's VLAN (the "trunk"). The script auto-detects subnet and gateway from this interface.

## Per-machine config

`.env.local` (gitignored) controls everything per-machine. Example:

```sh
# Trunk NIC. Defaults to enp2s0; set to whatever your cluster VLAN interface is.
export SBC_HOST_NIC=enp2s0

# Optional: pin gateway / override static zone IPs.
# export SBC_LAN_GATEWAY=10.0.100.1
# export SBC_INSIDE_IP=10.0.100.240
# export SBC_OUTSIDE_IP=10.0.100.241
# export SBC_OOBM_IP=10.0.100.242
```

LAN subnet and gateway are auto-detected from the trunk NIC. Static zone IPs default to `.240/.241/.242` of the detected /24 — override if those collide with the upstream DHCP scope.

## Usage

```sh
./setup.sh        # idempotent: deletes any existing 'sbc-local' cluster first
./teardown.sh
```

`setup.sh` will:

1. Create a kind cluster (`sbc-local`).
2. Build and load the SBC Docker image from the repo root.
3. Install standard CNI plugins, Multus CNI, and MetalLB inside the cluster.
4. Attach the kind node to a Docker `macvlan` rooted at `$SBC_HOST_NIC`.
5. Apply the `sbc-system` namespace, ConfigMaps, RBAC, NetworkAttachmentDefinitions, DaemonSet, and Services.
6. Add `iptables` rules in `DOCKER-USER` so NodePort traffic from the LAN can reach the kind bridge.
7. Print the zone IPs and access URLs.

## After setup completes

The SBC daemon serves the API and the embedded Angular dashboard from the same `:8080` listener on the **OOBM zone IP**.

| Surface       | URL                                                  |
|---------------|------------------------------------------------------|
| Dashboard     | `http://<oobm-ip>:8080/`                             |
| REST API      | `http://<oobm-ip>:8080/api/v1/...`                   |
| Metrics       | `http://<oobm-ip>:9090/metrics`                      |
| SIP (inside)  | `<inside-ip>:5060` UDP/TCP, `:5061` TLS              |
| SIP (outside) | `<outside-ip>:5060` UDP/TCP                          |
| RTP           | `<outside-ip>:16384-20000` UDP                       |

`<oobm-ip>`, `<inside-ip>`, `<outside-ip>` come from `.env.local` (or the auto-derived defaults).

## Troubleshooting

- **Pods stuck in `ContainerCreating` with macvlan errors.** `master` interface mismatch — `setup.sh` auto-detects the in-node trunk; if it picks the wrong one, set `SBC_HOST_NIC` explicitly.
- **Dashboard returns "not yet embedded".** The Angular dashboard is built into the SBC binary by `cargo build --release` after running `npm run build` in `crates/sbc/sbc-dashboard/`. Build it first, then `./setup.sh` rebuilds the image.
- **`promiscuous mode` permission errors.** The script runs `sudo ip link set <nic> promisc on`. Confirm your user has sudo for `ip` commands.
- **Pods can't reach the LAN.** Check the `DOCKER-USER` iptables chain — `setup.sh` adds ACCEPT rules for NodePorts 30560/30561/30880/30990 from the trunk NIC. If your host runs `firewalld` or similar, those rules may be filtered.
