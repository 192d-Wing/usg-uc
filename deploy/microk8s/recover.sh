#!/bin/bash
# Recovery for stale host-local CNI IPAM leases on the macvlan NADs.
#
# Symptom: pods stuck in ContainerCreating with
#   "error adding container to network ...: failed to allocate for range 0:
#    no IP addresses available in range set: 10.x.x.x-10.x.x.x"
#
# Cause: the host-local IPAM plugin (used by every NAD with /32-pinned
# ranges) writes a lease file at /var/lib/cni/networks/<nad>/<ip>. If a
# pod is force-deleted or its sandbox creation fails after host-local
# has allocated but before macvlan attaches, the file leaks and the
# next pod sees the IP as taken.
#
# Run as: sudo bash recover.sh

set -euo pipefail

NS="sbc-system"
NADS=(sbc-inside sbc-outside sbc-oobm kea-phones)

echo "[1/4] Tear down workloads (force, grace=0)..."
microk8s kubectl -n "$NS" delete daemonset sbc-daemon --grace-period=0 --force 2>/dev/null || true
microk8s kubectl -n "$NS" delete deployment kea-dhcp4 --grace-period=0 --force 2>/dev/null || true

echo "[2/4] Wait for pods=0 (max 60s)..."
for i in $(seq 1 30); do
  cnt=$(microk8s kubectl -n "$NS" get pods -o name 2>/dev/null | wc -l)
  [ "$cnt" = "0" ] && { echo "  pods=0 after ${i}*2s"; break; }
  sleep 2
done

echo "[3/4] Wipe stale leases..."
for net in "${NADS[@]}"; do
  rm -fv "/var/lib/cni/networks/$net"/10.* \
         "/var/lib/cni/networks/$net"/last_reserved_ip.0 2>&1 | sed 's/^/  /'
done

echo "[4/4] Reapply..."
cd "$(dirname "$0")"
microk8s kubectl apply -f kea-deployment.yaml -f sbc-daemonset.yaml
microk8s kubectl -n "$NS" rollout status deploy/kea-dhcp4 --timeout=120s || true
microk8s kubectl -n "$NS" rollout status daemonset/sbc-daemon --timeout=180s || true

echo
microk8s kubectl -n "$NS" get pods -o wide
