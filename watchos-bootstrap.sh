#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_one() {
  local sdk_name="$1"      # iphoneos, iphonesimulator, watchos, watchsimulator
  local min_os="$2"        # e.g. 17.0, 11.0, 10.0
  local archs="$3"         # e.g. arm64 or "arm64;x86_64"
  local build_dir="$ROOT/build-$sdk_name"

  echo "==> Configuring for $sdk_name $archs $min_os in $build_dir"

  mkdir -p "$build_dir"
  cmake "$ROOT" \
    -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT="$sdk_name" \
    -DCMAKE_OSX_ARCHITECTURES="$archs" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$min_os"

  echo "==> Building TrustWalletCore for $sdk_name $archs $min_os"
  cmake --build "$build_dir" --target TrustWalletCore --config Release
}

# iOS device (you’re targeting iOS 18 anyway, so 17 as a floor is plenty)
build_one iphoneos       "17.0" "arm64"

# watchOS device – aligned delete exists on modern watchOS; pick a sane floor
build_one watchos        "10.0" "arm64"

# iOS sim
build_one iphonesimulator "17.0" "arm64;x86_64"

# watchOS sim
build_one watchsimulator "10.0" "arm64;x86_64"

echo "✅ Finished building TrustWalletCore for iOS + watchOS"
