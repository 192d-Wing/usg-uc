#!/usr/bin/env bash
# Builds the iOS app for the iOS Simulator.
#
# Pipeline:
#   1. ./build-xcframework.sh — builds the Rust core staticlibs (incl. the iOS
#      and iOS-simulator slices), regenerates the Swift bindings, and assembles
#      ClientFFI.xcframework + the staged aws-lc FIPS dylibs.
#   2. xcodegen generate — regenerates ios/SipClientApp-iOS.xcodeproj from
#      ios/project.yml (the project is generated, not committed).
#   3. xcodebuild — builds SipClientApp-iOS for the iOS Simulator.
#
# Usage: ./build-ios-app.sh [--release] [--skip-framework] [-- <xcodebuild args>]
#   --release         pass --release to build-xcframework.sh (optimized core)
#   --skip-framework  skip step 1 (reuse an existing xcframework)
#
# Requires xcodegen (brew install xcodegen).

set -euo pipefail

cd "$(dirname "$0")"
IOS_DIR="$PWD/ios"

RELEASE=0
SKIP_FRAMEWORK=0
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) RELEASE=1; shift ;;
        --skip-framework) SKIP_FRAMEWORK=1; shift ;;
        --) shift; EXTRA_ARGS=("$@"); break ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if ! command -v xcodegen >/dev/null 2>&1; then
    echo "error: xcodegen not found — install it with: brew install xcodegen" >&2
    exit 1
fi

if [[ "$SKIP_FRAMEWORK" -eq 0 ]]; then
    echo "==> Building ClientFFI.xcframework (incl. iOS slices)"
    if [[ "$RELEASE" -eq 1 ]]; then
        ./build-xcframework.sh --release
    else
        ./build-xcframework.sh
    fi
else
    echo "==> Skipping framework build (--skip-framework)"
fi

echo "==> Generating Xcode project from ios/project.yml"
(cd "$IOS_DIR" && xcodegen generate)

echo "==> Building SipClientApp-iOS for the iOS Simulator"
xcodebuild \
    -project "$IOS_DIR/SipClientApp-iOS.xcodeproj" \
    -scheme SipClientApp-iOS \
    -destination 'generic/platform=iOS Simulator' \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
    build

echo "==> Done. App built for the iOS Simulator."
echo "    To run it, boot a simulator and install the .app, e.g.:"
echo "      xcrun simctl boot 'iPhone 15' || true"
echo "      xcodebuild -project ios/SipClientApp-iOS.xcodeproj -scheme SipClientApp-iOS \\"
echo "        -destination 'platform=iOS Simulator,name=iPhone 15' build"
