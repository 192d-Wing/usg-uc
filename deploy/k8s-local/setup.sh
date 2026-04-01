#!/usr/bin/env bash
# USG SBC — Local K8s cluster bootstrap
#
# Creates a kind cluster with Multus (multi-interface) and MetalLB
# (bare-metal LoadBalancer) for three-zone SBC testing:
#   - inside  (192.168.44.200) — SIP signaling
#   - outside (192.168.44.201) — RTP media
#   - oobm    (192.168.44.202) — management API
#
# Prerequisites: docker, kind, kubectl
# Install: brew install kind kubectl
#
# Usage: ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="sbc-local"
SBC_IMAGE="sbc-daemon:local"

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
command -v docker >/dev/null 2>&1 || fail "docker not found. Install Docker Desktop."
command -v kind   >/dev/null 2>&1 || fail "kind not found. Run: brew install kind"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. Run: brew install kubectl"
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
ok "MetalLB pools configured (192.168.44.200-202)"

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
info "Creating Multus NetworkAttachmentDefinitions..."
kubectl apply -f "$SCRIPT_DIR/multus-networks.yaml"
ok "Networks created (sbc-inside, sbc-outside, sbc-oobm)"

# ── Step 9: Apply SBC ConfigMap ──────────────────────────
info "Applying SBC configuration..."
kubectl apply -f "$SCRIPT_DIR/sbc-configmap.yaml"
ok "ConfigMap applied"

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

# ── Step 13: Print status ────────────────────────────────
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

echo "Access:"
echo "  Signaling (SIP):  192.168.44.200:5060"
echo "  Media (RTP):      192.168.44.201 (direct macvlan)"
echo "  OOBM (API):       http://192.168.44.202:8080"
echo ""

echo "Quick test:"
echo "  curl http://192.168.44.202:8080/api/v1/system/health"
echo ""

echo "Logs:"
echo "  kubectl -n sbc-system logs -f -l app.kubernetes.io/name=sbc"
echo ""

echo "Interfaces inside pod:"
echo "  kubectl -n sbc-system exec -it \$(kubectl -n sbc-system get pod -l app.kubernetes.io/name=sbc -o name | head -1) -- ip addr show"
echo ""

echo "Teardown:"
echo "  $SCRIPT_DIR/teardown.sh"
