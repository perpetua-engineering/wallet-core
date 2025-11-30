#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${ROOT}/build/apple"
XCFRAMEWORK_PATH="${ROOT}/build/WalletCore.xcframework"
HEADER_STAGE="${BUILD_ROOT}/headers"

# Expect these artifacts to already exist.
IOS_DEV_LIB="${BUILD_ROOT}/iphoneos-arm64/libTrustWalletCore.a"
IOS_SIM_ARM64_LIB="${BUILD_ROOT}/iphonesimulator-arm64/libTrustWalletCore.a"
IOS_SIM_X64_LIB="${BUILD_ROOT}/iphonesimulator-x86_64/libTrustWalletCore.a"
WATCH_DEV_ARM6432_LIB="${BUILD_ROOT}/watchos-arm64_32/libTrustWalletCore.a"
WATCH_SIM_ARM64_LIB="${BUILD_ROOT}/watchsimulator-arm64/libTrustWalletCore.a"
WATCH_SIM_X64_LIB="${BUILD_ROOT}/watchsimulator-x86_64/libTrustWalletCore.a"
MAC_ARM64_LIB="${BUILD_ROOT}/macosx-arm64/libTrustWalletCore.a"
MAC_X64_LIB="${BUILD_ROOT}/macosx-x86_64/libTrustWalletCore.a"

IOS_SIM_UNIV="${BUILD_ROOT}/libWalletCore-ios-sim-universal.a"
WATCH_SIM_UNIV="${BUILD_ROOT}/libWalletCore-watch-sim-universal.a"
MAC_UNIV="${BUILD_ROOT}/libWalletCore-macos-universal.a"

# Recreate fat sim libs in case slices changed.
echo "==> Creating fat simulator libs"
lipo -create "$IOS_SIM_ARM64_LIB" "$IOS_SIM_X64_LIB" -output "$IOS_SIM_UNIV"
lipo -create "$WATCH_SIM_ARM64_LIB" "$WATCH_SIM_X64_LIB" -output "$WATCH_SIM_UNIV"
lipo -create "$MAC_ARM64_LIB" "$MAC_X64_LIB" -output "$MAC_UNIV"

# Ensure headers exist; rewrite modulemap to current schema.
if [[ ! -d "$HEADER_STAGE" ]]; then
  echo "Missing headers stage at $HEADER_STAGE. Run tools/build-apple.sh first." >&2
  exit 1
fi
cat > "${HEADER_STAGE}/module.modulemap" <<'EOF'
module WalletCore {
  umbrella "TrustWalletCore"
  export *
  module * { export * }
  explicit module Rust {
    requires cplusplus
    header "WalletCoreRSBindgen.h"
    export *
  }
}
EOF

# Recreate XCFramework
rm -rf "$XCFRAMEWORK_PATH"
echo "==> Creating XCFramework at ${XCFRAMEWORK_PATH}"
xcodebuild -create-xcframework \
  -library "$IOS_DEV_LIB" -headers "$HEADER_STAGE" \
  -library "$IOS_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$WATCH_DEV_ARM6432_LIB" -headers "$HEADER_STAGE" \
  -library "$WATCH_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$MAC_UNIV" -headers "$HEADER_STAGE" \
  -output "$XCFRAMEWORK_PATH"

echo "✅ XCFramework rebuilt: ${XCFRAMEWORK_PATH}"
