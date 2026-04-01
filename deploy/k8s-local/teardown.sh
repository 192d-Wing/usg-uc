#!/usr/bin/env bash
# USG SBC — Tear down local K8s cluster
#
# Usage: ./teardown.sh

set -euo pipefail

CLUSTER_NAME="sbc-local"

echo "Deleting kind cluster '${CLUSTER_NAME}'..."
kind delete cluster --name "$CLUSTER_NAME"
echo "Cluster deleted."
