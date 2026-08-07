#!/usr/bin/env bash
# Link and optionally execute the RFC6979 probe against a shipped Android .so.

set -euo pipefail

if [[ $# -ne 2 && $# -ne 4 ]]; then
  echo "Usage: $0 <libwallet_core.so> <arm64-v8a|armeabi-v7a> [--serial <adb-serial>]" >&2
  exit 2
fi

ARTIFACT="$1"
ABI="$2"
SERIAL=""
if [[ $# -eq 4 ]]; then
  if [[ "$3" != "--serial" ]]; then
    echo "Expected --serial, got: $3" >&2
    exit 2
  fi
  SERIAL="$4"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROBE_SOURCE="$ROOT/tools/rfc6979-signature-probe.cpp"
if [[ ! -f "$ARTIFACT" ]]; then
  echo "Android WalletCore artifact not found: $ARTIFACT" >&2
  exit 1
fi

SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
NDK_ROOT="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK_ROOT" ]]; then
  NDK_ROOT="$(find "$SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
fi
if [[ ! -d "$NDK_ROOT" ]]; then
  echo "Android NDK not found: $NDK_ROOT" >&2
  exit 1
fi

host_tag=""
for candidate in darwin-x86_64 darwin-arm64 linux-x86_64; do
  if [[ -d "$NDK_ROOT/toolchains/llvm/prebuilt/$candidate" ]]; then
    host_tag="$candidate"
    break
  fi
done
if [[ -z "$host_tag" ]]; then
  echo "Android NDK host toolchain not found under: $NDK_ROOT" >&2
  exit 1
fi

case "$ABI" in
  arm64-v8a) clang_prefix=aarch64-linux-android ;;
  armeabi-v7a) clang_prefix=armv7a-linux-androideabi ;;
  *) echo "Unsupported Android ABI: $ABI" >&2; exit 2 ;;
esac

toolchain="$NDK_ROOT/toolchains/llvm/prebuilt/$host_tag"
clangxx="$toolchain/bin/${clang_prefix}30-clang++"
readelf_tool="$toolchain/bin/llvm-readelf"
for tool in "$clangxx" "$readelf_tool"; do
  if [[ ! -x "$tool" ]]; then
    echo "Missing Android verifier tool: $tool" >&2
    exit 1
  fi
done

VERIFY_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/walletcore-android-rfc6979.XXXXXX")"
trap 'rm -rf -- "$VERIFY_TMP_DIR"' EXIT

dynamic_symbols="$VERIFY_TMP_DIR/dynamic-symbols.txt"
"$readelf_tool" --dyn-syms "$ARTIFACT" >"$dynamic_symbols"
if ! grep -Eq '[[:space:]]FUNC[[:space:]]+GLOBAL.*TWCryptographRFC6979Mode$' "$dynamic_symbols"; then
  echo "Android RFC6979 verification failed for $ABI:" >&2
  echo "  final libwallet_core.so lacks the ecdsa.c mode attestation" >&2
  exit 1
fi

negative_log="$VERIFY_TMP_DIR/negative-build.log"
if printf '%s\n' '#include <TrezorCrypto/options.h>' | \
  "$clangxx" \
    -DCRYPTOGRAPH_REQUIRE_RFC6979=1 \
    -DUSE_RFC6979=0 \
    -I"$ROOT/trezor-crypto/include" \
    -x c++ -c - -o "$VERIFY_TMP_DIR/negative-build.o" \
    >"$negative_log" 2>&1; then
  echo "Android RFC6979 negative build fixture failed for $ABI:" >&2
  echo "  USE_RFC6979=0 compiled successfully" >&2
  exit 1
fi
if ! grep -Fq 'Cryptograph WalletCore requires USE_RFC6979=1' "$negative_log"; then
  echo "Android RFC6979 negative build fixture failed unexpectedly for $ABI:" >&2
  cat "$negative_log" >&2
  exit 1
fi

artifact_dir="$(cd "$(dirname "$ARTIFACT")" && pwd)"
probe_binary="$VERIFY_TMP_DIR/rfc6979-probe"
"$clangxx" \
  -std=c++17 -I"$ROOT/include/TrustWalletCore" "$PROBE_SOURCE" \
  -L"$artifact_dir" -lwallet_core -lc++_shared -llog -ldl -lm \
  '-Wl,-rpath,$ORIGIN' -o "$probe_binary"

artifact_dynamic="$VERIFY_TMP_DIR/artifact-dynamic.txt"
probe_dynamic="$VERIFY_TMP_DIR/probe-dynamic.txt"
"$readelf_tool" -d "$ARTIFACT" >"$artifact_dynamic"
"$readelf_tool" -d "$probe_binary" >"$probe_dynamic"
artifact_soname="$(sed -nE 's/.*Library soname: \[([^]]+)\].*/\1/p' "$artifact_dynamic")"
if [[ -z "$artifact_soname" ]]; then
  echo "Android RFC6979 verification failed for $ABI:" >&2
  echo "  final libwallet_core.so has no ELF SONAME" >&2
  exit 1
fi
if ! grep -Fq "Shared library: [$artifact_soname]" "$probe_dynamic"; then
  echo "Android RFC6979 verification failed for $ABI:" >&2
  echo "  probe is not linked to the final libwallet_core.so" >&2
  exit 1
fi

echo "  ok $ABI: final libwallet_core.so attested and production-linked"

if [[ -n "$SERIAL" ]]; then
  adb_bin="${ADB:-$SDK_ROOT/platform-tools/adb}"
  if [[ ! -x "$adb_bin" ]]; then
    echo "adb not found: $adb_bin" >&2
    exit 1
  fi
  if [[ "$("$adb_bin" -s "$SERIAL" get-state 2>/dev/null)" != "device" ]]; then
    echo "Android device is not ready: $SERIAL" >&2
    exit 1
  fi

  cxx_shared="$artifact_dir/libc++_shared.so"
  if [[ ! -f "$cxx_shared" ]]; then
    cxx_shared="$(find "$toolchain/sysroot/usr/lib" -path "*/$ABI/libc++_shared.so" -print -quit)"
  fi
  if [[ ! -f "$cxx_shared" ]]; then
    echo "libc++_shared.so not found for $ABI" >&2
    exit 1
  fi

  remote_dir="/data/local/tmp/cryptograph-rfc6979-$ABI"
  "$adb_bin" -s "$SERIAL" shell mkdir -p "$remote_dir"
  "$adb_bin" -s "$SERIAL" push "$ARTIFACT" "$remote_dir/$artifact_soname" >/dev/null
  "$adb_bin" -s "$SERIAL" push "$cxx_shared" "$remote_dir/libc++_shared.so" >/dev/null
  "$adb_bin" -s "$SERIAL" push "$probe_binary" "$remote_dir/rfc6979-probe" >/dev/null
  "$adb_bin" -s "$SERIAL" shell chmod 700 "$remote_dir/rfc6979-probe"
  "$adb_bin" -s "$SERIAL" shell \
    "cd '$remote_dir' && LD_LIBRARY_PATH=. ./rfc6979-probe"
  echo "  ok $ABI: RFC6979 known-answer signature executed on $SERIAL"
else
  echo "  note $ABI: pass --serial to execute the linked probe on an Android emulator"
fi
