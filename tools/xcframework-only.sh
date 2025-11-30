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
WATCH_DEV_ARM64_LIB="${BUILD_ROOT}/watchos-arm64/libTrustWalletCore.a"
WATCH_SIM_ARM64_LIB="${BUILD_ROOT}/watchsimulator-arm64/libTrustWalletCore.a"
WATCH_SIM_X64_LIB="${BUILD_ROOT}/watchsimulator-x86_64/libTrustWalletCore.a"
MAC_ARM64_LIB="${BUILD_ROOT}/macosx-arm64/libTrustWalletCore.a"
MAC_X64_LIB="${BUILD_ROOT}/macosx-x86_64/libTrustWalletCore.a"

TREZOR_IOS_DEV="${BUILD_ROOT}/iphoneos-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_IOS_SIM_X64="${BUILD_ROOT}/iphonesimulator-x86_64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_DEV_ARM64="${BUILD_ROOT}/watchos-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_DEV_ARM6432="${BUILD_ROOT}/watchos-arm64_32/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_SIM_ARM64="${BUILD_ROOT}/watchsimulator-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_SIM_X64="${BUILD_ROOT}/watchsimulator-x86_64/trezor-crypto/libTrezorCrypto.a"
TREZOR_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_MAC_X64="${BUILD_ROOT}/macosx-x86_64/trezor-crypto/libTrezorCrypto.a"

PROTOBUF_IOS_DEV="${BUILD_ROOT}/iphoneos-arm64/libprotobuf.a"
PROTOBUF_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/libprotobuf.a"
PROTOBUF_IOS_SIM_X64="${BUILD_ROOT}/iphonesimulator-x86_64/libprotobuf.a"
PROTOBUF_WATCH_DEV_ARM64="${BUILD_ROOT}/watchos-arm64/libprotobuf.a"
PROTOBUF_WATCH_DEV_ARM6432="${BUILD_ROOT}/watchos-arm64_32/libprotobuf.a"
PROTOBUF_WATCH_SIM_ARM64="${BUILD_ROOT}/watchsimulator-arm64/libprotobuf.a"
PROTOBUF_WATCH_SIM_X64="${BUILD_ROOT}/watchsimulator-x86_64/libprotobuf.a"
PROTOBUF_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/libprotobuf.a"
PROTOBUF_MAC_X64="${BUILD_ROOT}/macosx-x86_64/libprotobuf.a"
RUST_IOS_DEV="${ROOT}/rust/target/aarch64-apple-ios/release/libwallet_core_rs.a"
RUST_IOS_SIM_ARM64="${ROOT}/rust/target/aarch64-apple-ios-sim/release/libwallet_core_rs.a"
RUST_IOS_SIM_X64="${ROOT}/rust/target/x86_64-apple-ios/release/libwallet_core_rs.a"
RUST_WATCH_DEV_ARM64="${ROOT}/rust/target/aarch64-apple-watchos/release/libwallet_core_rs.a"
RUST_WATCH_DEV_ARM6432="${ROOT}/rust/target/arm64_32-apple-watchos/release/libwallet_core_rs.a"
RUST_WATCH_SIM_ARM64="${ROOT}/rust/target/aarch64-apple-watchos-sim/release/libwallet_core_rs.a"
RUST_WATCH_SIM_X64="${ROOT}/rust/target/x86_64-apple-watchos-sim/release/libwallet_core_rs.a"
RUST_MAC_ARM64="${ROOT}/rust/target/aarch64-apple-darwin/release/libwallet_core_rs.a"
RUST_MAC_X64="${ROOT}/rust/target/x86_64-apple-darwin/release/libwallet_core_rs.a"

IOS_SIM_UNIV="${BUILD_ROOT}/libWalletCore-ios-sim-universal.a"
WATCH_SIM_UNIV="${BUILD_ROOT}/libWalletCore-watch-sim-universal.a"
MAC_UNIV="${BUILD_ROOT}/libWalletCore-macos-universal.a"
IOS_DEV_COMBINED="${BUILD_ROOT}/iphoneos-arm64/libWalletCore-combined.a"
IOS_SIM_ARM64_COMBINED="${BUILD_ROOT}/iphonesimulator-arm64/libWalletCore-combined.a"
IOS_SIM_X64_COMBINED="${BUILD_ROOT}/iphonesimulator-x86_64/libWalletCore-combined.a"
WATCH_DEV_ARM64_COMBINED="${BUILD_ROOT}/watchos-arm64/libWalletCore-combined.a"
WATCH_DEV_ARM6432_COMBINED="${BUILD_ROOT}/watchos-arm64_32/libWalletCore-combined.a"
WATCH_SIM_ARM64_COMBINED="${BUILD_ROOT}/watchsimulator-arm64/libWalletCore-combined.a"
WATCH_SIM_X64_COMBINED="${BUILD_ROOT}/watchsimulator-x86_64/libWalletCore-combined.a"
MAC_ARM64_COMBINED="${BUILD_ROOT}/macosx-arm64/libWalletCore-combined.a"
MAC_X64_COMBINED="${BUILD_ROOT}/macosx-x86_64/libWalletCore-combined.a"

combine_libs() {
  local out="$1"; shift
  libtool -static -o "$out" "$@"
}

# Recreate fat sim libs in case slices changed.
echo "==> Creating fat simulator libs"
combine_libs "$IOS_DEV_COMBINED" "$IOS_DEV_LIB" "$TREZOR_IOS_DEV" "$RUST_IOS_DEV"
combine_libs "$IOS_SIM_ARM64_COMBINED" "$IOS_SIM_ARM64_LIB" "$TREZOR_IOS_SIM_ARM64" "$RUST_IOS_SIM_ARM64" "$PROTOBUF_IOS_SIM_ARM64"
combine_libs "$IOS_SIM_X64_COMBINED" "$IOS_SIM_X64_LIB" "$TREZOR_IOS_SIM_X64" "$RUST_IOS_SIM_X64" "$PROTOBUF_IOS_SIM_X64"
combine_libs "$WATCH_DEV_ARM64_COMBINED" "$WATCH_DEV_ARM64_LIB" "$TREZOR_WATCH_DEV_ARM64" "$RUST_WATCH_DEV_ARM64" "$PROTOBUF_WATCH_DEV_ARM64"
combine_libs "$WATCH_DEV_ARM6432_COMBINED" "$WATCH_DEV_ARM6432_LIB" "$TREZOR_WATCH_DEV_ARM6432" "$RUST_WATCH_DEV_ARM6432" "$PROTOBUF_WATCH_DEV_ARM6432"
combine_libs "$WATCH_SIM_ARM64_COMBINED" "$WATCH_SIM_ARM64_LIB" "$TREZOR_WATCH_SIM_ARM64" "$RUST_WATCH_SIM_ARM64" "$PROTOBUF_WATCH_SIM_ARM64"
combine_libs "$WATCH_SIM_X64_COMBINED" "$WATCH_SIM_X64_LIB" "$TREZOR_WATCH_SIM_X64" "$RUST_WATCH_SIM_X64" "$PROTOBUF_WATCH_SIM_X64"
combine_libs "$MAC_ARM64_COMBINED" "$MAC_ARM64_LIB" "$TREZOR_MAC_ARM64" "$RUST_MAC_ARM64" "$PROTOBUF_MAC_ARM64"
combine_libs "$MAC_X64_COMBINED" "$MAC_X64_LIB" "$TREZOR_MAC_X64" "$RUST_MAC_X64" "$PROTOBUF_MAC_X64"

lipo -create "$IOS_SIM_ARM64_COMBINED" "$IOS_SIM_X64_COMBINED" -output "$IOS_SIM_UNIV"
lipo -create "$WATCH_SIM_ARM64_COMBINED" "$WATCH_SIM_X64_COMBINED" -output "$WATCH_SIM_UNIV"
lipo -create "$MAC_ARM64_COMBINED" "$MAC_X64_COMBINED" -output "$MAC_UNIV"

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
  -library "$IOS_DEV_COMBINED" -headers "$HEADER_STAGE" \
  -library "$IOS_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$WATCH_DEV_ARM64_COMBINED" -headers "$HEADER_STAGE" \
  -library "$WATCH_DEV_ARM6432_COMBINED" -headers "$HEADER_STAGE" \
  -library "$WATCH_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$MAC_UNIV" -headers "$HEADER_STAGE" \
  -output "$XCFRAMEWORK_PATH"

echo "✅ XCFramework rebuilt: ${XCFRAMEWORK_PATH}"
