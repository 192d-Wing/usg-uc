#!/usr/bin/env bash
# USG SBC — Local K8s cluster bootstrap
#
# Creates a kind cluster with Multus (multi-interface) and MetalLB
# (bare-metal LoadBalancer) for three-zone SBC testing:
#   - inside  (DHCP) — SIP signaling
#   - outside (DHCP) — RTP media + STUN external IP discovery
#   - oobm    (DHCP) — management API
#
# Macvlan interfaces get IPs via DHCP from the physical LAN.
# The LAN subnet and gateway are auto-detected from the host NIC.
#
# Prerequisites: docker, kind, kubectl, python3
# Install (Linux): sudo apt-get install docker-ce; download kind & kubectl binaries
# Install (macOS): brew install kind kubectl
#
# Usage: ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="sbc-local"
SBC_IMAGE="sbc-daemon:local"
HOST_NIC="${SBC_HOST_NIC:-enp2s0}"       # Physical NIC for macvlan trunk
LAN_GATEWAY="${SBC_LAN_GATEWAY:-}"      # Auto-detected if empty
DOCKER_MACVLAN_NET="sbc-lan"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Preflight checks ─────────────────────────────────────
info "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || fail "docker not found. Install Docker (docker-ce or Docker Desktop)."
command -v kind   >/dev/null 2>&1 || fail "kind not found. See: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. See: https://kubernetes.io/docs/tasks/tools/"
docker info >/dev/null 2>&1 || fail "Docker daemon not running."
ok "Prerequisites satisfied"

# ── Step 1: Create kind cluster ───────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    warn "Cluster '${CLUSTER_NAME}' already exists. Deleting..."
    kind delete cluster --name "$CLUSTER_NAME"
fi

info "Creating kind cluster '${CLUSTER_NAME}' (single node)..."
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

# Remove control-plane taint and add SBC label so DaemonSets can schedule
info "Configuring node for SBC scheduling..."
kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>/dev/null || true
kubectl label nodes --all node-role.kubernetes.io/sbc=true --overwrite
ok "Cluster created"

# ── Step 1b: Attach Kind node to physical LAN via macvlan ─
# Auto-detect subnet and gateway from the host NIC
LAN_CIDR=$(ip -4 addr show "$HOST_NIC" | awk '/inet /{print $2}')
LAN_SUBNET=$(python3 -c "import ipaddress; n=ipaddress.ip_interface('$LAN_CIDR').network; print(n)" 2>/dev/null)
if [ -z "$LAN_GATEWAY" ]; then
    LAN_GATEWAY=$(ip route show default dev "$HOST_NIC" | awk '{print $3; exit}')
fi
[ -z "$LAN_SUBNET" ] && fail "Cannot detect subnet on ${HOST_NIC}"
[ -z "$LAN_GATEWAY" ] && fail "Cannot detect gateway on ${HOST_NIC}"
info "Detected LAN: subnet=${LAN_SUBNET} gateway=${LAN_GATEWAY}"

# macvlan requires promiscuous mode on the parent NIC so that frames
# addressed to child-interface MACs are delivered instead of dropped.
info "Enabling promiscuous mode on ${HOST_NIC}..."
sudo ip link set "$HOST_NIC" promisc on
ok "Promiscuous mode enabled"

info "Creating Docker macvlan network on ${HOST_NIC}..."
docker network rm "$DOCKER_MACVLAN_NET" 2>/dev/null || true
docker network create -d macvlan \
    --subnet="$LAN_SUBNET" \
    --gateway="$LAN_GATEWAY" \
    -o parent="$HOST_NIC" \
    "$DOCKER_MACVLAN_NET"

NODE_NAME=$(kind get nodes --name "$CLUSTER_NAME" | head -1)
info "Connecting node '${NODE_NAME}' to ${DOCKER_MACVLAN_NET} network..."
docker network connect "$DOCKER_MACVLAN_NET" "$NODE_NAME"

# Find the interface name assigned inside the node for the macvlan network
# It's the newest non-eth0/non-veth interface (e.g. eth1@if2)
MACVLAN_IF=$(docker exec "$NODE_NAME" bash -c '
    ip -o link show | awk -F"[ :@]+" "/eth[1-9]/{print \$2}" | tail -1
')
info "Macvlan trunk interface inside node: ${MACVLAN_IF}"
ok "Kind node connected to physical LAN via ${HOST_NIC}"

# ── Step 2: Build and load SBC image ─────────────────────
info "Building SBC Docker image..."
docker build -t "$SBC_IMAGE" "$PROJECT_ROOT" --quiet
ok "Image built: $SBC_IMAGE"

info "Loading image into kind cluster..."
kind load docker-image "$SBC_IMAGE" --name "$CLUSTER_NAME"
ok "Image loaded"

# ── Step 3: Install CNI plugins + Multus CNI ──────────────
info "Installing standard CNI plugins (macvlan, bridge, etc.) into kind node..."
for NODE in $(kind get nodes --name "$CLUSTER_NAME"); do
    docker exec "$NODE" bash -c '
        CNI_VERSION="v1.6.2"
        ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
        mkdir -p /opt/cni/bin
        curl -sSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | tar -xz -C /opt/cni/bin
    '
done
ok "CNI plugins installed"

info "Starting CNI DHCP daemon on kind node(s)..."
for NODE in $(kind get nodes --name "$CLUSTER_NAME"); do
    docker exec "$NODE" sh -c '
        # Kill any stale DHCP daemon and clean up
        killall -9 dhcp 2>/dev/null || true
        sleep 1
        rm -f /run/cni/dhcp.sock
        rm -rf /var/lib/cni/dhcp 2>/dev/null || true
        mkdir -p /run/cni

        /opt/cni/bin/dhcp daemon > /var/log/cni-dhcp.log 2>&1 &
        DHCP_PID=$!

        # Wait for the socket and verify the process is still alive
        for i in 1 2 3 4 5 6 7 8 9 10; do
            [ -S /run/cni/dhcp.sock ] && break
            sleep 0.5
        done

        if [ -S /run/cni/dhcp.sock ] && kill -0 $DHCP_PID 2>/dev/null; then
            echo "DHCP daemon ready (PID $DHCP_PID)"
        else
            echo "DHCP daemon failed to start"
            cat /var/log/cni-dhcp.log 2>/dev/null
            exit 1
        fi
    '
done
ok "CNI DHCP daemon started"

info "Installing Multus CNI..."
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml
kubectl -n kube-system rollout status daemonset/kube-multus-ds --timeout=120s
ok "Multus installed"

# ── Step 4: Install MetalLB ──────────────────────────────
info "Installing MetalLB..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.9/config/manifests/metallb-native.yaml

# Wait for MetalLB controller to be ready
info "Waiting for MetalLB controller..."
kubectl -n metallb-system rollout status deployment/controller --timeout=120s
kubectl -n metallb-system wait pod -l component=speaker --for=condition=Ready --timeout=120s
ok "MetalLB installed"

# ── Step 5: Configure MetalLB pools ──────────────────────
info "Configuring MetalLB IP pools..."
# Small delay to let MetalLB webhooks register
sleep 5
kubectl apply -f "$SCRIPT_DIR/metallb.yaml"
ok "MetalLB pools configured"

# ── Step 6: Create SBC namespace ─────────────────────────
info "Creating sbc-system namespace..."
kubectl apply -f "$SCRIPT_DIR/namespace.yaml"
ok "Namespace created"

# ── Step 7: Apply RBAC ───────────────────────────────────
if [ -f "$PROJECT_ROOT/deploy/kubernetes/rbac.yaml" ]; then
    info "Applying RBAC..."
    kubectl apply -f "$PROJECT_ROOT/deploy/kubernetes/rbac.yaml"
    ok "RBAC applied"
else
    warn "RBAC manifest not found, creating minimal ServiceAccount..."
    kubectl -n sbc-system create serviceaccount sbc-daemon --dry-run=client -o yaml | kubectl apply -f -
    ok "ServiceAccount created"
fi

# ── Step 8: Apply Multus networks ────────────────────────
info "Creating Multus NetworkAttachmentDefinitions (master=${MACVLAN_IF})..."
sed "s/\"master\": \"eth0\"/\"master\": \"${MACVLAN_IF}\"/" "$SCRIPT_DIR/multus-networks.yaml" | kubectl apply -f -
ok "Networks created (sbc-inside, sbc-outside, sbc-oobm)"

# ── Step 9: Apply SBC ConfigMaps ─────────────────────────
info "Applying SBC configuration..."
kubectl apply -f "$SCRIPT_DIR/sbc-configmap.yaml"
kubectl -n sbc-system create configmap sbc-network \
    --from-literal=lan_subnet="$LAN_SUBNET" \
    --from-literal=lan_gateway="$LAN_GATEWAY" \
    --dry-run=client -o yaml | kubectl apply -f -
ok "ConfigMaps applied"

# ── Step 10: Deploy SBC DaemonSet ────────────────────────
info "Deploying SBC DaemonSet..."
kubectl apply -f "$SCRIPT_DIR/sbc-daemonset.yaml"
ok "DaemonSet created"

# ── Step 11: Apply Services ──────────────────────────────
info "Creating zone Services (MetalLB)..."
kubectl apply -f "$SCRIPT_DIR/sbc-services.yaml"
ok "Services created"

# ── Step 12: Wait for SBC pod ────────────────────────────
info "Waiting for SBC pod to be ready (up to 5 minutes)..."
if kubectl -n sbc-system wait pod -l app.kubernetes.io/name=sbc --for=condition=Ready --timeout=300s 2>/dev/null; then
    ok "SBC pod is ready"
else
    warn "Pod not ready yet. Check: kubectl -n sbc-system describe pod -l app.kubernetes.io/name=sbc"
fi

# ── Step 13: Allow LAN access through Docker firewall ────
# Docker's FORWARD chain defaults to DROP. Add rules so that traffic
# arriving on the host NIC can reach the Kind node's NodePorts.
DOCKER_BRIDGE=$(docker network inspect kind -f '{{(index .Options "com.docker.network.bridge.name")}}' 2>/dev/null)
if [ -n "$DOCKER_BRIDGE" ]; then
    info "Adding iptables rules for LAN → Kind forwarding (${HOST_NIC} → ${DOCKER_BRIDGE})..."
    for PORT in 30560 30561 30880 30990; do
        sudo iptables -I DOCKER-USER -i "$HOST_NIC" -o "$DOCKER_BRIDGE" -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null
    done
    sudo iptables -I DOCKER-USER -i "$HOST_NIC" -o "$DOCKER_BRIDGE" -p udp --dport 30560 -j ACCEPT 2>/dev/null
    # MASQUERADE LAN traffic so the Kind node routes replies back through
    # the Docker bridge instead of out its macvlan interface (asymmetric routing fix).
    sudo iptables -t nat -I POSTROUTING -s "$LAN_SUBNET" -o "$DOCKER_BRIDGE" -j MASQUERADE 2>/dev/null
    ok "LAN forwarding rules added"
else
    warn "Could not detect Docker bridge name for Kind network"
fi

# ── Step 14: Print status ────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  USG SBC Local K8s Cluster — Ready${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""

echo "Pods:"
kubectl -n sbc-system get pods -o wide
echo ""

echo "Services:"
kubectl -n sbc-system get svc
echo ""

SBC_POD=$(kubectl -n sbc-system get pod -l app.kubernetes.io/name=sbc -o name 2>/dev/null | head -1)
if [ -n "$SBC_POD" ]; then
    POD_STATUS=$(kubectl -n sbc-system get "$SBC_POD" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null)
    echo "Macvlan IPs (DHCP-assigned):"
    echo "$POD_STATUS" | python3 -c "
import sys,json
for net in json.load(sys.stdin):
    if net.get('interface','').startswith('net'):
        ips = ', '.join(net.get('ips', ['pending']))
        print(f\"  {net['name'].split('/')[-1]:12s} ({net['interface']}): {ips}\")
" 2>/dev/null || echo "  (waiting for DHCP leases...)"
    echo ""
fi

echo "Host access (via Kind extraPortMappings):"
echo "  SIP (UDP/TCP):  localhost:5060"
echo "  SIP TLS:        localhost:5061"
echo "  OOBM API:       http://localhost:8080"
echo "  Metrics:        http://localhost:9090"
echo ""

echo "LAN access (macvlan DHCP — from other devices on the LAN):"
echo "  Use the DHCP IPs shown above for direct pod access."
echo "  Media (RTP) flows via the outside macvlan interface directly."
echo ""

echo "Quick test:"
echo "  curl http://localhost:8080/api/v1/system/health"
echo ""

echo "Logs:"
echo "  kubectl -n sbc-system logs -f -l app.kubernetes.io/name=sbc"
echo ""

echo "Teardown:"
echo "  $SCRIPT_DIR/teardown.sh"
