#!/usr/bin/env bash
# USG SBC — Tear down local K8s cluster
#
# Usage: ./teardown.sh

set -euo pipefail

CLUSTER_NAME="sbc-local"
HOST_NIC="${SBC_HOST_NIC:-enp2s0}"
DOCKER_MACVLAN_NET="sbc-lan"

echo "Cleaning up iptables forwarding rules..."
DOCKER_BRIDGE=$(docker network inspect kind -f '{{(index .Options "com.docker.network.bridge.name")}}' 2>/dev/null)
if [ -n "$DOCKER_BRIDGE" ]; then
    for PORT in 30560 30561 30880 30990; do
        sudo iptables -D DOCKER-USER -i "$HOST_NIC" -o "$DOCKER_BRIDGE" -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    done
    sudo iptables -D DOCKER-USER -i "$HOST_NIC" -o "$DOCKER_BRIDGE" -p udp --dport 30560 -j ACCEPT 2>/dev/null || true
    sudo iptables -t nat -D POSTROUTING -s 192.168.0.0/24 -o "$DOCKER_BRIDGE" -j MASQUERADE 2>/dev/null || true
fi

echo "Deleting kind cluster '${CLUSTER_NAME}'..."
kind delete cluster --name "$CLUSTER_NAME"

echo "Removing Docker macvlan network '${DOCKER_MACVLAN_NET}'..."
docker network rm "$DOCKER_MACVLAN_NET" 2>/dev/null || true

echo "Disabling promiscuous mode on ${HOST_NIC}..."
sudo ip link set "$HOST_NIC" promisc off 2>/dev/null || true

echo "Cluster deleted."
