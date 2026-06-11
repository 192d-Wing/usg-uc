# Microk8s deploy — SBC + Kea DHCP

Single-node microk8s deployment of the USG SBC plus an ISC Kea DHCPv4 server
that hands TEO IP phones their provisioning URL.

## Network layout

| Component       | VLAN | Subnet           | Static IP        |
|-----------------|------|------------------|------------------|
| SBC inside      | 3000 | 10.0.100.0/24    | 10.0.100.240     |
| SBC outside     | 3000 | 10.0.100.0/24    | 10.0.100.241     |
| SBC oobm        | 3000 | 10.0.100.0/24    | 10.0.100.242     |
| Kea DHCP server | 3001 | 10.0.101.0/24    | 10.0.101.2       |
| Phone DHCP pool | 3001 | 10.0.101.0/24    | 10.0.101.100-200 |

VLANs ride a single trunked NIC (`ens192`). Per-VLAN host sub-interfaces
(`ens192.3000`, `ens192.3001`) are the macvlan `master` for each CNI
NetworkAttachmentDefinition.

## TEO phone provisioning

Kea hands phones on VLAN 3001 these DHCP options:

| Option | Name                 | Value                                |
|--------|----------------------|--------------------------------------|
| 3      | routers              | `10.0.101.1`                         |
| 6      | domain-name-servers  | `10.0.101.1`                         |
| 66     | tftp-server-name     | `sbc.xtic.dev.mil`                   |
| 67     | boot-file-name       | `provision`                          |
| 150    | tftp-server-address  | `10.0.100.240` (SBC **inside** zone) |
| 160    | (custom) firmware-url| `http://sbc.xtic.dev.mil/provision`  |

Phones land on the **inside** zone (`net1` = `10.0.100.240`), not oobm.
Option 66 is the hostname fallback; option 150 is the literal IP so no DNS
is required for the initial bootstrap. The SBC daemon serves the matching
XML at `http://<sbc-inside>/provision/<MAC>.xml`
(see `crates/uc/uc-phone-mgmt/src/teo.rs`).

## Prerequisites (one-time host setup)

1. **microk8s** installed (snap).
2. Current user in the `microk8s` group:
   ```sh
   sudo usermod -aG microk8s "$USER"
   newgrp microk8s  # or re-login
   ```
3. **VLAN 3001 sub-interface on the host.** This deploy assumes
   `ens192.3001` exists. For runtime only:
   ```sh
   sudo ip link add link ens192 name ens192.3001 type vlan id 3001
   sudo ip link set ens192 promisc on
   sudo ip link set ens192.3001 promisc on
   sudo ip link set ens192.3001 up
   ```
   To survive reboot, add it to `/etc/netplan/` (depends on your distro).
4. **Microk8s addons:**
   ```sh
   sudo microk8s enable community
   sudo microk8s enable multus
   sudo microk8s enable hostpath-storage
   ```

## SBC image — required before applying `sbc-daemonset.yaml`

The SBC daemonset references `image: usg-sbc-daemon:local` with
`imagePullPolicy: Never`. Microk8s containerd must already have this image.
Build externally (Linux box with docker + Rust + Node), then import:

```sh
# On a build host:
docker build -t usg-sbc-daemon:local .
docker save sbc-daemon:local -o sbc-daemon.tar

# Copy sbc-daemon.tar to the microk8s host, then:
sudo microk8s ctr image import sbc-daemon.tar
sudo microk8s ctr images ls | grep sbc-daemon  # verify
```

If you change the tag, update `image:` in `sbc-daemonset.yaml`.

## Apply order

```sh
cd deploy/microk8s
microk8s kubectl apply -f namespace.yaml
microk8s kubectl apply -f rbac.yaml
microk8s kubectl apply -f multus-networks.yaml
microk8s kubectl apply -f sbc-configmap.yaml
microk8s kubectl apply -f sbc-services.yaml

# TLS — generate a self-signed cert and load it as the sbc-tls Secret.
# Required before sbc-daemonset.yaml; the daemon mounts /etc/sbc/tls/.
sudo bash make-tls-secret.sh

# Kea (independent of SBC image — can deploy alone)
microk8s kubectl apply -f kea-configmap.yaml
microk8s kubectl apply -f kea-deployment.yaml

# SBC (requires sbc-daemon:local in containerd + sbc-tls Secret)
microk8s kubectl apply -f sbc-daemonset.yaml
```

## Verify

```sh
microk8s kubectl -n sbc-system get pods -o wide
microk8s kubectl -n sbc-system describe pod -l app.kubernetes.io/name=kea-dhcp4
microk8s kubectl -n sbc-system logs -l app.kubernetes.io/name=kea-dhcp4 --tail=50

# Confirm Kea bound to the macvlan interface:
microk8s kubectl -n sbc-system exec deploy/kea-dhcp4 -- ip -4 addr show net1

# Live DHCP discovery from a test client on VLAN 3001:
sudo dhcping -s 10.0.101.2 -c 10.0.101.50 -h <client-mac>
```

## Caveats

- **DNS for `sbc.xtic.dev.mil`.** Phones on VLAN 3001 receive
  `10.0.101.1` as their DNS server (Kea option 6). If that gateway
  resolves `sbc.xtic.dev.mil`, it must point to the SBC **inside** IP
  `10.0.100.240`. If DNS isn't viable, firmware that honors option 150
  will use the literal `10.0.100.240` instead.
- **Inter-VLAN routing.** Phones at 10.0.101.0/24 reaching the SBC at
  10.0.100.240 requires upstream router-on-a-stick or inter-VLAN ACLs
  you control. Not configured here.
- **Port mismatch.** The SBC API listens on `:8080`. Option 160 (and
  the URL the SBC emits in TEO XML at `teo.rs:70`) is portless,
  implying `:80`. Either bind the API to `:80` in `sbc-configmap.yaml`
  (needs `NET_BIND_SERVICE`, already granted), or front the daemon
  with something on `:80`. Not resolved here.
- **Pod Security.** The namespace runs at `privileged` enforcement to
  let Kea use `NET_RAW` and the SBC init container do policy routing.
- **TEO option 160 is a custom DHCP option.** The TEO firmware
  documentation determines which fields it actually parses; option 66
  is the most-portable fallback.
