#!/usr/bin/env bash
# One-shot triage of the CodeQL alerts open on 2026-10-10 (see PR #135).
# Dismisses alerts that are false positives, protocol-mandated, or confined to
# tests/examples/test tooling. Leaves #142 (rust/disabled-certificate-check in
# client-provisioning/src/http.rs) open pending a product decision, and leaves
# the actions/js alerts that PR #135 fixes to auto-close on merge.
#
# Usage: ci/dismiss-codeql-alerts.sh            (needs `gh auth` with security_events write)
set -euo pipefail

REPO=192d-Wing/usg-uc

dismiss() { # number reason comment
  gh api -X PATCH "repos/$REPO/code-scanning/alerts/$1" \
    -f state=dismissed -f dismissed_reason="$2" -f dismissed_comment="$3" \
    --jq '"\(.number) -> \(.state) (\(.dismissed_reason))"'
}

echo "== false positives: zero-initialised buffers overwritten before use"
for n in 59 60; do
  dismiss "$n" "false positive" "The [0u8; NONCE_LEN] array is a zero-initialised buffer immediately overwritten with the 4-byte implicit IV and 8-byte explicit record nonce (RFC 6347 AEAD nonce construction). No constant nonce is used."
done
dismiss 116 "false positive" "RFC 7714 section 8.1 IV construction: the two leading zero octets are mandated; SSRC, 48-bit packet index and the session salt supply the entropy. No constant nonce is used."
dismiss 63 "false positive" "[0u8; N] is a zero-initialised output buffer that fill_random() overwrites with CSPRNG bytes before it is returned."

echo "== won't fix: SIP Digest challenge-response hashing mandated by RFC, not password storage"
dismiss 146 "won't fix" "SIP Digest (RFC 3261) MD5 for interop with peers that do not support RFC 8760 SHA-256. Feature-gated behind digest-auth; production government builds are mTLS-only. Challenge-response hashing, not password storage."
dismiss 153 "won't fix" "SIP Digest (RFC 3261/8760) algorithm selection: MD5 only when the peer negotiates it. Challenge-response hashing per protocol, not password storage."
dismiss 145 "won't fix" "RFC 7616 SIP Digest HA1 = SHA-256(username:realm:password) is mandated by the protocol. Challenge-response hashing, not password storage."

echo "== used in tests: #[cfg(test)] fixtures, examples, integration tests, deploy/test tooling"
TEST_MODULE="Inside a #[cfg(test)] module: unit-test fixture value, not compiled into production builds."
EXAMPLE="Example program; the value is a placeholder used only for the walkthrough and never ships in a binary."
INTEG="Integration test fixture."
STRESS="Load-test tooling under deploy/test that runs only inside the test compose network; binding all interfaces is intentional there."

# rust/hard-coded-cryptographic-value inside #[cfg(test)] modules
for n in 15 16 17 18 97 139 140 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 \
         35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 \
         57 64 91 133 134 86 87 92 93 90 81 135 136 82 137; do
  dismiss "$n" "used in tests" "$TEST_MODULE"
done
# examples/
for n in 138 129 130 131; do dismiss "$n" "used in tests" "$EXAMPLE"; done
# client-integration-tests
for n in 128 132; do dismiss "$n" "used in tests" "$INTEG"; done
# deploy/test python stress tools
for n in 76 77 78 79 80; do dismiss "$n" "used in tests" "$STRESS"; done

echo "== still open"
gh api --paginate "repos/$REPO/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | "\(.number)\t\(.rule.id)\t\(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'
