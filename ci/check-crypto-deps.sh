#!/usr/bin/env bash
# Crypto dependency gate (SR-16), cargo-tree checks only.
#
#   1. `ring` is absent from the normal-dependency graph of every shipped
#      binary, on every target.
#   2. `aws-lc-fips-sys` (the FIPS 140-3 aws-lc module) is present in every
#      SBC / central image binary.
#   3. RustCrypto `hmac` (and `hkdf`) reach an image binary or uc-auth
#      only through sqlx-postgres. First-party HMAC-SHA-384 runs in the
#      FIPS module via uc-crypto; sqlx-postgres SCRAM authentication uses
#      RustCrypto outside the module (POA&M-403).
#
# Runnable locally from any directory: ci/check-crypto-deps.sh
# Exits non-zero and lists every failure. Extra cargo flags (for example
# --locked or --offline) can be passed in CARGO_TREE_FLAGS.
#
# NIST 800-53 Rev5: SC-13, SR-3, CM-7
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

# shellcheck disable=SC2206 # intentional word splitting of extra flags
EXTRA=(${CARGO_TREE_FLAGS:-})

# Every shipped binary package; "pkg|features" runs with --features.
RING_FREE=(
    "sbc-daemon|"
    "sbc-daemon|full"
    "sbc-cli|"
    "sbc-media|"
    "sbc-api-server|"
    "sbc-provision-server|"
    "sbc-client-config-server|"
    "sbc-announcement-server|"
    "sbc-trunk-agent|"
    "central-config-api|"
    "central-config-import|"
    "sbc-config-sync|"
    "client-ffi|"
    "client-gui-tauri|"
)

# The SBC / central container image binaries.
FIPS_REQUIRED=(
    "sbc-daemon|"
    "sbc-daemon|full"
    "sbc-cli|"
    "sbc-media|"
    "sbc-api-server|"
    "sbc-provision-server|"
    "sbc-client-config-server|"
    "sbc-announcement-server|"
    "sbc-trunk-agent|"
    "central-config-api|"
    "central-config-import|"
    "sbc-config-sync|"
)

# Where RustCrypto HMAC may be used: "crate|allowed direct parents".
# POAM: POA&M-403 - sqlx-postgres SCRAM-SHA-256 runs outside the FIPS module.
HMAC_ALLOWED_PARENTS=(
    "hmac|hkdf sqlx-postgres"
    "hkdf|sqlx-postgres"
)
HMAC_SCOPE=(
    "uc-auth|"
    "${FIPS_REQUIRED[@]}"
)

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# tree_inverted <crate> <pkg> <features> [extra cargo-tree args...]
# Prints the inverted tree on stdout. Returns 0 = crate found in the graph
# (stdout non-empty), 3 = not in the graph, anything else = error. "Absent"
# is a distinct code so any shell or cargo failure fails closed.
tree_inverted() {
    local crate=$1 pkg=$2 feats=$3
    shift 3
    local args=(tree ${EXTRA[@]+"${EXTRA[@]}"} -e normal -i "$crate" -p "$pkg" "$@")
    [[ -n $feats ]] && args+=(--features "$feats")
    local out err rc
    err=$(mktemp)
    out=$(cargo "${args[@]}" 2>"$err")
    rc=$?
    if [[ $rc -ne 0 ]]; then
        # Not in Cargo.lock at all: cargo reports a spec mismatch.
        if grep -q "did not match any packages" "$err"; then
            rm -f "$err"
            return 3
        fi
        cat "$err" >&2
        rm -f "$err"
        return 2
    fi
    rm -f "$err"
    if [[ -n $out ]]; then
        printf '%s\n' "$out"
        return 0
    fi
    return 3
}

label() {
    local pkg=$1 feats=$2
    if [[ -n $feats ]]; then echo "$pkg --features $feats"; else echo "$pkg"; fi
}

check_absent() {
    local crate=$1 entry=$2
    shift 2
    local pkg=${entry%%|*} feats=${entry#*|} out rc
    out=$(tree_inverted "$crate" "$pkg" "$feats" "$@")
    rc=$?
    case $rc in
        0)
            fail "$crate is in the dependency graph of $(label "$pkg" "$feats"):"
            printf '%s\n' "$out" | sed 's/^/    /' >&2
            ;;
        3) echo "ok: no $crate in $(label "$pkg" "$feats")" ;;
        *) fail "cargo tree failed for $(label "$pkg" "$feats")" ;;
    esac
}

check_present() {
    local crate=$1 entry=$2
    shift 2
    local pkg=${entry%%|*} feats=${entry#*|} rc
    tree_inverted "$crate" "$pkg" "$feats" "$@" >/dev/null
    rc=$?
    case $rc in
        0) echo "ok: $crate in $(label "$pkg" "$feats")" ;;
        3) fail "$crate is missing from $(label "$pkg" "$feats") (binary does not link the FIPS module)" ;;
        *) fail "cargo tree failed for $(label "$pkg" "$feats")" ;;
    esac
}

echo "== ring absent (all targets)"
for e in "${RING_FREE[@]}"; do check_absent ring "$e" --target all; done

# check_parents <crate> <allowed parents> <entry> [extra cargo-tree args...]
# Fails when any direct dependent of <crate> is not in the allowed list.
check_parents() {
    local crate=$1 allowed=$2 entry=$3
    shift 3
    local pkg=${entry%%|*} feats=${entry#*|} out rc parent bad=()
    out=$(tree_inverted "$crate" "$pkg" "$feats" --depth 1 --prefix none "$@")
    rc=$?
    case $rc in
        0) ;;
        3) echo "ok: no $crate in $(label "$pkg" "$feats")"; return ;;
        *) fail "cargo tree failed for $(label "$pkg" "$feats")"; return ;;
    esac
    while read -r parent _; do
        [[ -z $parent || $parent == "$crate" ]] && continue
        [[ " $allowed " == *" $parent "* ]] || bad+=("$parent")
    done <<<"$out"
    if [[ ${#bad[@]} -ne 0 ]]; then
        fail "$crate used by ${bad[*]} in $(label "$pkg" "$feats") (allowed: $allowed; POA&M-403)"
    else
        echo "ok: $crate in $(label "$pkg" "$feats") only via $allowed"
    fi
}

echo "== aws-lc-fips-sys present"
for e in "${FIPS_REQUIRED[@]}"; do check_present aws-lc-fips-sys "$e"; done

echo "== RustCrypto hmac only via sqlx-postgres (POA&M-403)"
for a in "${HMAC_ALLOWED_PARENTS[@]}"; do
    for e in "${HMAC_SCOPE[@]}"; do
        check_parents "${a%%|*}" "${a#*|}" "$e" --target all
    done
done

if [[ $failures -ne 0 ]]; then
    echo "check-crypto-deps: $failures failure(s)" >&2
    exit 1
fi
echo "check-crypto-deps: all checks passed"
