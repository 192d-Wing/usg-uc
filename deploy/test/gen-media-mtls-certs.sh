#!/usr/bin/env bash
# Generates a throwaway ECDSA P-384 / SHA-384 PKI for the media-node pool
# compose stack (docker-compose.pool.yml): a test CA, one server certificate
# per media node (IP SANs 172.28.2.11 and 172.28.2.12) and the daemon's client
# certificate (SAN DNS sbc-daemon, on SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES).
#
# TEST ONLY. Output always goes to a `media-mtls` subdirectory of the base
# directory (default deploy/test/certs, gitignored), and only the files this
# script writes are replaced there. The leaf keys are made world-readable so the containers'
# non-root user can read the bind mount; never use these files elsewhere.
#
# Usage: bash deploy/test/gen-media-mtls-certs.sh [base-dir]
#
# NIST 800-53 Rev5: IA-3, SC-8 (mTLS on the media control channel)
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=${1:-"$script_dir/certs"}
out="$base/media-mtls"
days=7

mkdir -p "$out"
cd "$out"
# Only the names this script produces (never a glob over the directory).
files=(ca.crt ca.key ca.srl)
for n in media-1 media-2 sbc-daemon; do
  files+=("$n.crt" "$n.key" "$n.csr" "$n.ext")
done
rm -f -- "${files[@]}"

key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1"
}

# Test CA.
key ca.key
openssl req -x509 -new -sha384 -key ca.key -days "$days" \
  -subj "/CN=sbc-test-media-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

# leaf <name> <subjectAltName> <extendedKeyUsage>
leaf() {
  local name=$1 san=$2 eku=$3
  key "$name.key"
  openssl req -new -sha384 -key "$name.key" -subj "/CN=$name" -out "$name.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\nkeyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\n' \
    "$san" "$eku" > "$name.ext"
  openssl x509 -req -sha384 -in "$name.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days "$days" -extfile "$name.ext" -out "$name.crt"
  rm -f "$name.csr" "$name.ext"
}

leaf media-1 "IP:172.28.2.11" serverAuth
leaf media-2 "IP:172.28.2.12" serverAuth
leaf sbc-daemon "DNS:sbc-daemon" clientAuth

# The CA key is not mounted into any container; drop it.
rm -f ca.key ca.srl
chmod 0644 ca.crt media-1.crt media-1.key media-2.crt media-2.key \
  sbc-daemon.crt sbc-daemon.key
echo "media mTLS test certificates written to $out"
