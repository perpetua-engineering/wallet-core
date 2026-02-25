#!/usr/bin/env bash
#
# Build TrustWalletCore for Apple platforms and assemble an XCFramework.
#
# Modes:
#   (default)  Full release build: 9 arch slices (iOS + watchOS + macOS), ~30-45 min
#   --dev      Dev build: 2 slices (macOS arm64 + iOS sim arm64), incremental, ~3-5 min
#
# The --dev xcframework is enough for `swift test` (macOS) and simulator builds
# (iOS arm64) but NOT for TestFlight, device, or watchOS.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${ROOT}/build/apple"
XCFRAMEWORK_PATH="${ROOT}/build/WalletCore.xcframework"
HEADER_STAGE="${BUILD_ROOT}/headers"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"
IOS_MIN="${IOS_MIN:-17.0}"
WATCH_MIN="${WATCH_MIN:-10.0}"
MAC_MIN="${MAC_MIN:-14.0}"

# Parse --dev flag
DEV_MODE=false
for arg in "$@"; do
  case "$arg" in
    --dev) DEV_MODE=true ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1" >&2; exit 1; }
}

require_cmd cmake
require_cmd xcodebuild
require_cmd xcrun

if $DEV_MODE; then
  echo "==> DEV MODE: building macOS arm64 + iOS sim arm64 only (incremental)"
else
  echo "==> FULL BUILD: all 9 arch slices"
fi

echo "==> Generating bindings (protos + WalletCoreRSBindgen.h)"
if [[ "${SKIP_CODEGEN:-0}" != "1" ]]; then
  # Avoid running xcodegen/pod if not needed (set SKIP_XCODEGEN=0 to force).
  export SKIP_XCODEGEN="${SKIP_XCODEGEN:-1}"
  "${ROOT}/tools/generate-files" ios
else
  echo "Skipping codegen because SKIP_CODEGEN=1"
fi

# Shared Rust target dir — Cargo handles its own file locking, so multiple
# agents/worktrees can safely point here. Avoids redundant 7+ min Rust
# compiles when only C++ changed.
RUST_TARGET_DIR="${RUST_TARGET_DIR:-${HOME}/.cryptograph/cache/rust-target/wallet-core}"
mkdir -p "$RUST_TARGET_DIR"

ensure_rust_lib() {
  local target="$1"
  local out="${RUST_TARGET_DIR}/${target}/release/libwallet_core_rs.a"

  # Pin deployment targets so Rust objects match the C++ slices.
  # Without this, rustc defaults to the active SDK version (e.g. 26.0)
  # which produces "built for newer macOS/iOS" linker warnings.
  case "$target" in
    *-apple-watchos*)
      export WATCHOS_DEPLOYMENT_TARGET="$WATCH_MIN" ;;
    *-apple-ios*)
      export IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN" ;;
    *-apple-darwin*)
      export MACOSX_DEPLOYMENT_TARGET="$MAC_MIN" ;;
  esac

  if ! rustc --print target-list | grep -q "$target"; then
    echo "Rust target ${target} not installed. Add it via: rustup target add ${target}" >&2
    exit 1
  fi

  if [[ ! -f "$out" ]]; then
    echo "==> Building Rust target ${target}"
    pushd "${ROOT}/rust" >/dev/null
    RUSTFLAGS="-Zlocation-detail=none" CARGO_TARGET_DIR="$RUST_TARGET_DIR" \
      cargo +nightly build -Z build-std=std,panic_abort --target "$target" --release --lib
    popd >/dev/null
  fi

  echo "$out"
}

build_slice() {
  local sdk="$1"       # iphoneos, iphonesimulator, watchos, watchsimulator
  local min_os="$2"    # e.g. 17.0
  local arch="$3"      # e.g. arm64
  local rust_target="$4"
  local out_var="$5"   # name of variable to fill with lib path

  local build_dir="${BUILD_ROOT}/${sdk}-${arch}"
  local sdk_path
  sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"

  # In dev mode, keep the build dir for incremental CMake rebuilds.
  # In full mode, always start clean for reproducible release builds.
  if $DEV_MODE; then
    if [[ -f "${build_dir}/CMakeCache.txt" ]]; then
      echo "==> Incremental rebuild ${sdk} ${arch}"
    else
      echo "==> Configuring ${sdk} ${arch} (min ${min_os})"
      cmake -S "$ROOT" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_SYSROOT="$sdk_path" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="$min_os" \
        -DCMAKE_OSX_ARCHITECTURES="$arch" \
        -DWALLET_CORE_RS_TARGET_DIR="${RUST_TARGET_DIR}/${rust_target}"
    fi
  else
    echo "==> Configuring ${sdk} ${arch} (min ${min_os})"
    rm -rf "$build_dir"
    cmake -S "$ROOT" -B "$build_dir" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_OSX_SYSROOT="$sdk_path" \
      -DCMAKE_OSX_DEPLOYMENT_TARGET="$min_os" \
      -DCMAKE_OSX_ARCHITECTURES="$arch" \
      -DWALLET_CORE_RS_TARGET_DIR="${RUST_TARGET_DIR}/${rust_target}"
  fi

  echo "==> Building TrustWalletCore for ${sdk} ${arch}"
  cmake --build "$build_dir" --config Release --target TrustWalletCore -- -j"$JOBS"

  local out_path="${build_dir}/libTrustWalletCore.a"
  printf -v "$out_var" "%s" "$out_path"
}

combine_libs() {
  local out="$1"; shift
  libtool -static -o "$out" "$@"
}

stage_headers() {
  echo "==> Staging headers"
  rm -rf "$HEADER_STAGE"
  mkdir -p "$HEADER_STAGE"
  cp -R "${ROOT}/include/." "$HEADER_STAGE/"
  cp "${ROOT}/src/rust/bindgen/WalletCoreRSBindgen.h" "$HEADER_STAGE/"
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
}

mkdir -p "$BUILD_ROOT"

# ─── Dev mode: 2 slices, incremental, minimal xcframework ───
if $DEV_MODE; then
  ensure_rust_lib aarch64-apple-darwin
  ensure_rust_lib aarch64-apple-ios-sim

  build_slice macosx "$MAC_MIN" arm64 aarch64-apple-darwin MAC_ARM64_LIB
  build_slice iphonesimulator "$IOS_MIN" arm64 aarch64-apple-ios-sim IOS_SIM_ARM64_LIB

  TREZOR_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/trezor-crypto/libTrezorCrypto.a"
  PROTOBUF_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/libprotobuf.a"
  RUST_MAC_ARM64="${RUST_TARGET_DIR}/aarch64-apple-darwin/release/libwallet_core_rs.a"
  MAC_ARM64_COMBINED="${BUILD_ROOT}/macosx-arm64/libWalletCore-combined.a"

  TREZOR_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/trezor-crypto/libTrezorCrypto.a"
  PROTOBUF_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/libprotobuf.a"
  RUST_IOS_SIM_ARM64="${RUST_TARGET_DIR}/aarch64-apple-ios-sim/release/libwallet_core_rs.a"
  IOS_SIM_ARM64_COMBINED="${BUILD_ROOT}/iphonesimulator-arm64/libWalletCore-combined.a"

  echo "==> Combining libs (dev)"
  combine_libs "$MAC_ARM64_COMBINED" "$MAC_ARM64_LIB" "$TREZOR_MAC_ARM64" "$RUST_MAC_ARM64" "$PROTOBUF_MAC_ARM64"
  combine_libs "$IOS_SIM_ARM64_COMBINED" "$IOS_SIM_ARM64_LIB" "$TREZOR_IOS_SIM_ARM64" "$RUST_IOS_SIM_ARM64" "$PROTOBUF_IOS_SIM_ARM64"

  stage_headers

  echo "==> Creating XCFramework (dev) at ${XCFRAMEWORK_PATH}"
  rm -rf "$XCFRAMEWORK_PATH"
  xcodebuild -create-xcframework \
    -library "$IOS_SIM_ARM64_COMBINED" -headers "$HEADER_STAGE" \
    -library "$MAC_ARM64_COMBINED" -headers "$HEADER_STAGE" \
    -output "$XCFRAMEWORK_PATH"

  echo "✅ Dev build done. XCFramework at ${XCFRAMEWORK_PATH}"
  echo "   Platforms: macOS arm64, iOS Simulator arm64"
  echo "   Good for: swift test, simulator builds"
  echo "   NOT for: TestFlight, device, watchOS"
  exit 0
fi

# ─── Full build: all 9 slices ───
ensure_rust_lib aarch64-apple-ios
ensure_rust_lib aarch64-apple-ios-sim
ensure_rust_lib x86_64-apple-ios
ensure_rust_lib aarch64-apple-watchos
ensure_rust_lib arm64_32-apple-watchos
ensure_rust_lib aarch64-apple-watchos-sim
ensure_rust_lib x86_64-apple-watchos-sim
ensure_rust_lib aarch64-apple-darwin
ensure_rust_lib x86_64-apple-darwin

build_slice watchos "$WATCH_MIN" arm64_32 arm64_32-apple-watchos WATCH_DEV_ARM6432_LIB
build_slice iphoneos "$IOS_MIN" arm64 aarch64-apple-ios IOS_DEV_LIB
build_slice watchos "$WATCH_MIN" arm64 aarch64-apple-watchos WATCH_DEV_ARM64_LIB
build_slice iphonesimulator "$IOS_MIN" arm64 aarch64-apple-ios-sim IOS_SIM_ARM64_LIB
build_slice iphonesimulator "$IOS_MIN" x86_64 x86_64-apple-ios IOS_SIM_X64_LIB
build_slice watchsimulator "$WATCH_MIN" arm64 aarch64-apple-watchos-sim WATCH_SIM_ARM64_LIB
build_slice watchsimulator "$WATCH_MIN" x86_64 aarch64-apple-watchos-sim WATCH_SIM_X64_LIB
build_slice macosx "$MAC_MIN" arm64 aarch64-apple-darwin MAC_ARM64_LIB
build_slice macosx "$MAC_MIN" x86_64 x86_64-apple-darwin MAC_X64_LIB

IOS_SIM_UNIV="${BUILD_ROOT}/libWalletCore-ios-sim-universal.a"
WATCH_SIM_UNIV="${BUILD_ROOT}/libWalletCore-watch-sim-universal.a"
WATCH_DEV_UNIV="${BUILD_ROOT}/libWalletCore-watch-dev-universal.a"
# Xcode prefers static libs prefixed with lib*.a inside XCFrameworks.
MAC_UNIV="${BUILD_ROOT}/libWalletCore-macos-universal.a"

# Paths to dependent static libs per arch.
TREZOR_IOS_DEV="${BUILD_ROOT}/iphoneos-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_IOS_SIM_X64="${BUILD_ROOT}/iphonesimulator-x86_64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_DEV_ARM64="${BUILD_ROOT}/watchos-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_DEV_ARM6432="${BUILD_ROOT}/watchos-arm64_32/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_SIM_ARM64="${BUILD_ROOT}/watchsimulator-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_WATCH_SIM_X64="${BUILD_ROOT}/watchsimulator-x86_64/trezor-crypto/libTrezorCrypto.a"
TREZOR_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/trezor-crypto/libTrezorCrypto.a"
TREZOR_MAC_X64="${BUILD_ROOT}/macosx-x86_64/trezor-crypto/libTrezorCrypto.a"

PROTOBUF_WATCH_DEV_ARM64="${BUILD_ROOT}/watchos-arm64/libprotobuf.a"
PROTOBUF_IOS_DEV="${BUILD_ROOT}/iphoneos-arm64/libprotobuf.a"
PROTOBUF_IOS_SIM_ARM64="${BUILD_ROOT}/iphonesimulator-arm64/libprotobuf.a"
PROTOBUF_IOS_SIM_X64="${BUILD_ROOT}/iphonesimulator-x86_64/libprotobuf.a"
PROTOBUF_WATCH_DEV_ARM6432="${BUILD_ROOT}/watchos-arm64_32/libprotobuf.a"
PROTOBUF_WATCH_SIM_ARM64="${BUILD_ROOT}/watchsimulator-arm64/libprotobuf.a"
PROTOBUF_WATCH_SIM_X64="${BUILD_ROOT}/watchsimulator-x86_64/libprotobuf.a"
PROTOBUF_MAC_ARM64="${BUILD_ROOT}/macosx-arm64/libprotobuf.a"
PROTOBUF_MAC_X64="${BUILD_ROOT}/macosx-x86_64/libprotobuf.a"

RUST_WATCH_DEV_ARM64="${RUST_TARGET_DIR}/aarch64-apple-watchos/release/libwallet_core_rs.a"
RUST_IOS_DEV="${RUST_TARGET_DIR}/aarch64-apple-ios/release/libwallet_core_rs.a"
RUST_IOS_SIM_ARM64="${RUST_TARGET_DIR}/aarch64-apple-ios-sim/release/libwallet_core_rs.a"
RUST_IOS_SIM_X64="${RUST_TARGET_DIR}/x86_64-apple-ios/release/libwallet_core_rs.a"
RUST_WATCH_DEV_ARM6432="${RUST_TARGET_DIR}/arm64_32-apple-watchos/release/libwallet_core_rs.a"
RUST_WATCH_SIM_ARM64="${RUST_TARGET_DIR}/aarch64-apple-watchos-sim/release/libwallet_core_rs.a"
RUST_WATCH_SIM_X64="${RUST_TARGET_DIR}/x86_64-apple-watchos-sim/release/libwallet_core_rs.a"
RUST_MAC_ARM64="${RUST_TARGET_DIR}/aarch64-apple-darwin/release/libwallet_core_rs.a"
RUST_MAC_X64="${RUST_TARGET_DIR}/x86_64-apple-darwin/release/libwallet_core_rs.a"

IOS_DEV_COMBINED="${BUILD_ROOT}/iphoneos-arm64/libWalletCore-combined.a"
IOS_SIM_ARM64_COMBINED="${BUILD_ROOT}/iphonesimulator-arm64/libWalletCore-combined.a"
IOS_SIM_X64_COMBINED="${BUILD_ROOT}/iphonesimulator-x86_64/libWalletCore-combined.a"
WATCH_DEV_ARM64_COMBINED="${BUILD_ROOT}/watchos-arm64/libWalletCore-combined.a"
WATCH_DEV_ARM6432_COMBINED="${BUILD_ROOT}/watchos-arm64_32/libWalletCore-combined.a"
WATCH_SIM_ARM64_COMBINED="${BUILD_ROOT}/watchsimulator-arm64/libWalletCore-combined.a"
WATCH_SIM_X64_COMBINED="${BUILD_ROOT}/watchsimulator-x86_64/libWalletCore-combined.a"
MAC_ARM64_COMBINED="${BUILD_ROOT}/macosx-arm64/libWalletCore-combined.a"
MAC_X64_COMBINED="${BUILD_ROOT}/macosx-x86_64/libWalletCore-combined.a"

echo "==> Creating fat simulator libs"
combine_libs "$IOS_DEV_COMBINED" "$IOS_DEV_LIB" "$TREZOR_IOS_DEV" "$RUST_IOS_DEV" "$PROTOBUF_IOS_DEV"
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
lipo -create "$WATCH_DEV_ARM64_COMBINED" "$WATCH_DEV_ARM6432_COMBINED" -output "$WATCH_DEV_UNIV"
lipo -create "$MAC_ARM64_COMBINED" "$MAC_X64_COMBINED" -output "$MAC_UNIV"

stage_headers

echo "==> Creating XCFramework at ${XCFRAMEWORK_PATH}"
rm -rf "$XCFRAMEWORK_PATH"
xcodebuild -create-xcframework \
  -library "$IOS_DEV_COMBINED" -headers "$HEADER_STAGE" \
  -library "$IOS_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$WATCH_DEV_UNIV" -headers "$HEADER_STAGE" \
  -library "$WATCH_SIM_UNIV" -headers "$HEADER_STAGE" \
  -library "$MAC_UNIV" -headers "$HEADER_STAGE" \
  -output "$XCFRAMEWORK_PATH"

echo "✅ Done. XCFramework available at ${XCFRAMEWORK_PATH}"
