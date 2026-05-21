#!/bin/bash
# Generate a self-signed TLS cert for the SBC API server and load it as the
# `sbc-tls` Secret in the `sbc-system` namespace. For lab / test use only.
#
# Phones (TEO) won't trust this cert, so /provision still flows over HTTP
# unless you replace this with a CA-issued certificate.
#
# Usage: sudo bash make-tls-secret.sh

set -euo pipefail

NS="sbc-system"
SECRET="sbc-tls"
CN="${SBC_TLS_CN:-sbc.xtic.dev.mil}"
DAYS="${SBC_TLS_DAYS:-825}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/openssl.cnf" <<EOF
[req]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req
x509_extensions    = v3_req

[dn]
C  = US
ST = Lab
L  = USG
O  = USG SBC
CN = $CN

[v3_req]
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt

[alt]
DNS.1 = $CN
DNS.2 = sbc-oobm.sbc-system.svc.cluster.local
IP.1  = 10.0.100.240
IP.2  = 10.0.100.241
IP.3  = 10.0.100.242
IP.4  = 127.0.0.1
EOF

openssl req -x509 -nodes -days "$DAYS" \
  -newkey rsa:4096 \
  -keyout "$TMP/tls.key" -out "$TMP/tls.crt" \
  -config "$TMP/openssl.cnf"

echo "Generated cert:"
openssl x509 -in "$TMP/tls.crt" -noout -subject -issuer -dates -ext subjectAltName

microk8s kubectl -n "$NS" delete secret "$SECRET" --ignore-not-found
microk8s kubectl -n "$NS" create secret tls "$SECRET" \
  --cert="$TMP/tls.crt" --key="$TMP/tls.key"

echo
echo "Secret $NS/$SECRET ready. Pods may need a rollout-restart to pick it up:"
echo "  microk8s kubectl -n $NS rollout restart daemonset/sbc-daemon"
