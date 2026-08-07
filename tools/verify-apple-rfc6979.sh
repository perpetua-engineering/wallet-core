#!/usr/bin/env bash
# Verify the RFC6979 signing-mode contract in every Apple WalletCore slice.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <WalletCore.xcframework>" >&2
  exit 2
fi

XCFRAMEWORK_PATH="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROBE_SOURCE="$ROOT/tools/rfc6979-signature-probe.cpp"
if [[ ! -d "$XCFRAMEWORK_PATH" ]]; then
  echo "WalletCore XCFramework not found: $XCFRAMEWORK_PATH" >&2
  exit 1
fi

for command_name in ar arch codesign lipo nm python3 xcrun; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required tool: $command_name" >&2
    exit 1
  fi
done

VERIFY_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/walletcore-rfc6979.XXXXXX")"
trap 'rm -rf -- "$VERIFY_TMP_DIR"' EXIT

negative_regression() {
  local log="$VERIFY_TMP_DIR/negative-build.log"
  if printf '%s\n' '#include <TrezorCrypto/options.h>' | \
    xcrun --sdk macosx clang \
      -DCRYPTOGRAPH_REQUIRE_RFC6979=1 \
      -DUSE_RFC6979=0 \
      -I"$ROOT/trezor-crypto/include" \
      -x c -c - -o "$VERIFY_TMP_DIR/negative-build.o" \
      >"$log" 2>&1; then
    echo "RFC6979 negative build fixture failed:" >&2
    echo "  USE_RFC6979=0 compiled successfully" >&2
    exit 1
  fi
  if ! grep -Fq 'Cryptograph WalletCore requires USE_RFC6979=1' "$log"; then
    echo "RFC6979 negative build fixture failed for an unexpected reason:" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "  ok negative build: USE_RFC6979=0 is rejected"
}

platform_link_flags() {
  local library_identifier="$1"
  case "$library_identifier" in
    ios-*simulator*)
      printf '%s\n' iphonesimulator "-mios-simulator-version-min=${IOS_MIN:-17.0}"
      ;;
    ios-*)
      printf '%s\n' iphoneos "-miphoneos-version-min=${IOS_MIN:-17.0}"
      ;;
    watchos-*simulator*)
      printf '%s\n' watchsimulator "-mwatchos-simulator-version-min=${WATCH_MIN:-10.0}"
      ;;
    watchos-*)
      printf '%s\n' watchos "-mwatchos-version-min=${WATCH_MIN:-10.0}"
      ;;
    macos-*)
      printf '%s\n' macosx "-mmacosx-version-min=${MAC_MIN:-14.0}"
      ;;
    *)
      echo "Unsupported XCFramework library identifier: $library_identifier" >&2
      return 1
      ;;
  esac
}

simulator_udid() {
  local family="$1"
  xcrun simctl list devices available -j | python3 -c '
import json, sys
family = sys.argv[1]
devices = json.load(sys.stdin)["devices"]
for runtime, entries in devices.items():
    if family not in runtime:
        continue
    for entry in entries:
        if entry.get("isAvailable", True):
            print(entry["udid"])
            raise SystemExit(0)
raise SystemExit(1)
' "$family"
}

retarget_probe() {
  local source_binary="$1"
  local output_binary="$2"
  local platform="$3"
  local minimum_version="$4"
  local sdk_version="$5"

  xcrun vtool \
    -set-build-version "$platform" "$minimum_version" "$sdk_version" \
    -replace -output "$output_binary" "$source_binary"
  chmod +x "$output_binary"
  codesign --force --sign - "$output_binary" >/dev/null
}

run_behavioral_probe() {
  local probe_binary="$1"
  local library_identifier="$2"
  local architecture="$3"
  local output_dir="$4"
  local runnable="$probe_binary"

  case "$library_identifier/$architecture" in
    macos-*/arm64)
      "$runnable"
      ;;
    macos-*/x86_64)
      arch -x86_64 "$runnable"
      ;;
    ios-*simulator*/arm64)
      xcrun simctl spawn --standalone "$(simulator_udid iOS)" "$runnable"
      ;;
    ios-*simulator*/x86_64|watchos-*simulator*/x86_64)
      runnable="$output_dir/probe-macos"
      retarget_probe \
        "$probe_binary" "$runnable" macos "${MAC_MIN:-14.0}" \
        "$(xcrun --sdk macosx --show-sdk-version)"
      arch -x86_64 "$runnable"
      ;;
    ios-*/arm64)
      runnable="$output_dir/probe-simulator"
      retarget_probe \
        "$probe_binary" "$runnable" iossim "${IOS_MIN:-17.0}" \
        "$(xcrun --sdk iphonesimulator --show-sdk-version)"
      xcrun simctl spawn --standalone "$(simulator_udid iOS)" "$runnable"
      ;;
    watchos-*simulator*/arm64)
      xcrun simctl spawn --standalone "$(simulator_udid watchOS)" "$runnable"
      ;;
    watchos-*/arm64)
      runnable="$output_dir/probe-simulator"
      retarget_probe \
        "$probe_binary" "$runnable" watchossim "${WATCH_MIN:-10.0}" \
        "$(xcrun --sdk watchsimulator --show-sdk-version)"
      xcrun simctl spawn --standalone "$(simulator_udid watchOS)" "$runnable"
      ;;
    watchos-*/arm64_32)
      # Apple Silicon simulators cannot execute the watch device-only arm64_32
      # ABI. The exact slice is still compile-attested and production-linked;
      # all runnable slices execute the identical known-answer probe.
      echo "  note ${library_identifier}/${architecture}: device-only ABI linked and attested"
      return 2
      ;;
    *)
      echo "Unsupported Apple probe target: ${library_identifier}/${architecture}" >&2
      return 1
      ;;
  esac
}

negative_regression

verified_architectures=0
executed_architectures=0
while IFS= read -r archive_path; do
  library_identifier="$(basename "$(dirname "$archive_path")")"
  architectures="$(lipo -archs "$archive_path")"

  for architecture in $architectures; do
    architecture_dir="$VERIFY_TMP_DIR/${library_identifier}-${architecture}"
    header_dir="$(dirname "$archive_path")/Headers/TrustWalletCore"
    thin_archive="$architecture_dir/WalletCore.a"
    probe_binary="$architecture_dir/probe"
    link_map="$architecture_dir/probe.map"
    mkdir -p "$architecture_dir"

    if [[ "$architectures" == "$architecture" ]]; then
      cp "$archive_path" "$thin_archive"
    else
      lipo "$archive_path" -thin "$architecture" -output "$thin_archive"
    fi

    symbols="$architecture_dir/symbols.txt"
    nm -m -o "$thin_archive" >"$symbols"
    if ! grep -Eq \
      'ecdsa\.c\.o:.*external _TWCryptographRFC6979Mode$' \
      "$symbols"; then
      echo "RFC6979 verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  ecdsa.c.o does not attest the production RFC6979 mode" >&2
      exit 1
    fi

    {
      IFS= read -r sdk_name
      IFS= read -r minimum_version_flag
    } < <(platform_link_flags "$library_identifier")

    xcrun --sdk "$sdk_name" clang++ \
      -std=c++17 -arch "$architecture" "$minimum_version_flag" \
      -I"$header_dir" "$PROBE_SOURCE" "$thin_archive" \
      -framework Security -framework CoreFoundation -lz \
      -Wl,-dead_strip "-Wl,-map,$link_map" \
      -o "$probe_binary"

    if ! grep -Fq '_TWCryptographRFC6979Mode' "$link_map" || \
       ! grep -Fq 'ecdsa.c.o' "$link_map" || \
       ! grep -Fq '_TWPrivateKeySign' "$link_map" || \
       ! grep -Fq 'PrivateKey.cpp.o' "$link_map" || \
       ! grep -Fq '_ecdsa_sign_digest' "$link_map"; then
      echo "RFC6979 verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  production-linked probe did not bind the final WalletCore signing path" >&2
      exit 1
    fi

    if run_behavioral_probe \
      "$probe_binary" "$library_identifier" "$architecture" "$architecture_dir"; then
      echo "  ok ${library_identifier}/${architecture}: RFC6979 known-answer signature"
      executed_architectures=$((executed_architectures + 1))
    else
      result=$?
      if [[ $result -ne 2 ]]; then
        echo "RFC6979 behavioral probe failed for ${library_identifier}/${architecture}" >&2
        exit 1
      fi
    fi
    verified_architectures=$((verified_architectures + 1))
  done
done < <(find "$XCFRAMEWORK_PATH" -mindepth 2 -maxdepth 2 -type f -name '*.a' | sort)

if [[ $verified_architectures -eq 0 ]]; then
  echo "RFC6979 verification failed: no static libraries found in $XCFRAMEWORK_PATH" >&2
  exit 1
fi

echo "Verified RFC6979 mode in ${verified_architectures} Apple architecture(s); executed ${executed_architectures} runnable slice(s)."
