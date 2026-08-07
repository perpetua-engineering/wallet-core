#!/usr/bin/env bash
# Verify that every architecture in an Apple WalletCore XCFramework resolves
# mnemonic generation to the Security-framework RNG implementation, and that
# omitting that provider is a *link-time* failure rather than a silent
# downgrade to trezor-crypto's /dev/urandom fallback.
#
# Two distinct properties are checked, and they are not interchangeable:
#
#   Structural — trezor-crypto/crypto/rand.c compiles to no RNG
#     definitions on Apple, so no archive member other than SecRandom.m.o can
#     satisfy random32 / random_buffer.  Dropping the provider makes the
#     production-equivalent link fail with unresolved symbols; there is no
#     runnable artifact left for a verifier to reject.
#
#   Post-link — the surviving positive proof that the archive we
#     actually ship binds random_buffer to SecRandom.m.o, imports
#     SecRandomCopyBytes, and carries no /dev/urandom string.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <WalletCore.xcframework>" >&2
  exit 2
fi

XCFRAMEWORK_PATH="$1"
if [[ ! -d "$XCFRAMEWORK_PATH" ]]; then
  echo "WalletCore XCFramework not found: $XCFRAMEWORK_PATH" >&2
  exit 1
fi

WALLET_CORE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FALLBACK_SOURCE="${WALLET_CORE_ROOT}/trezor-crypto/crypto/rand.c"
TREZOR_INCLUDE_DIR="${WALLET_CORE_ROOT}/trezor-crypto/include"

for command_name in ar lipo nm ranlib strings xcrun; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required tool: $command_name" >&2
    exit 1
  fi
done

if [[ ! -f "$FALLBACK_SOURCE" ]]; then
  echo "trezor-crypto RNG source not found: $FALLBACK_SOURCE" >&2
  exit 1
fi

VERIFY_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/walletcore-rng.XXXXXX")"
trap 'rm -rf "$VERIFY_TMP_DIR"' EXIT

verified_architectures=0
negative_regression_ran=false

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

# Production-equivalent probe: follow the mnemonic-generation entry point rather
# than calling random_buffer directly, so ld extracts the same WalletCore
# objects used by TWSecureSignerCreateWallet while dead stripping unused code.
emit_probe_source() {
  printf '%s\n' \
    '#include <stddef.h>' \
    'extern "C" const void *TWSecureSignerCreateWallet(const void *, const void *);' \
    'int main(void) {' \
    '  return TWSecureSignerCreateWallet(nullptr, nullptr) == nullptr;' \
    '}'
}

link_production_probe() {
  local archive_path="$1"
  local library_identifier="$2"
  local architecture="$3"
  local output_dir="$4"
  local sdk_name
  local minimum_version_flag
  local link_map="$output_dir/probe.map"
  local probe_binary="$output_dir/probe"

  mkdir -p "$output_dir"
  {
    IFS= read -r sdk_name
    IFS= read -r minimum_version_flag
  } < <(platform_link_flags "$library_identifier")

  emit_probe_source | xcrun --sdk "$sdk_name" clang++ \
      -arch "$architecture" \
      "$minimum_version_flag" \
      -x c++ - \
      -x none "$archive_path" \
      -framework Security \
      -framework CoreFoundation \
      -Wl,-dead_strip \
      "-Wl,-map,$link_map" \
      -o "$probe_binary"

  printf '%s\n' "$link_map" "$probe_binary"
}

assert_linked_provider() {
  local archive_path="$1"
  local library_identifier="$2"
  local architecture="$3"
  local output_dir="$4"
  local link_map
  local probe_binary
  local provider_index

  if ! {
    IFS= read -r link_map
    IFS= read -r probe_binary
  } < <(link_production_probe \
    "$archive_path" "$library_identifier" "$architecture" "$output_dir"); then
    echo "  production mnemonic link probe failed" >&2
    return 1
  fi

  provider_index="$(LC_ALL=C sed -nE \
    's/^\[ *([0-9]+)\].*\(SecRandom\.m\.o\)$/\1/p' "$link_map")"
  if [[ -z "$provider_index" ]]; then
    echo "  production mnemonic link did not load SecRandom.m.o" >&2
    return 1
  fi

  if ! grep -Eq \
    "^0x[0-9A-Fa-f]+[[:space:]]+0x[0-9A-Fa-f]+[[:space:]]+\[ *${provider_index}\][[:space:]]+_random_buffer$" \
    "$link_map"; then
    echo "  SecRandom.m.o did not satisfy _random_buffer in the link map" >&2
    return 1
  fi

  if grep -Eq '^\[ *[0-9]+\].*\(rand\.c\.o\)$' "$link_map"; then
    echo "  production mnemonic link loaded trezor rand.c.o" >&2
    return 1
  fi

  local import_check
  import_check="$(nm -u "$probe_binary" | grep -E '^_SecRandomCopyBytes$' || true)"
  if [[ -z "$import_check" ]]; then
    echo "  linked probe does not import SecRandomCopyBytes" >&2
    return 1
  fi

  # Read the whole stream: `grep -q` exits on the first match, which makes the
  # producer die of SIGPIPE and, under `set -o pipefail`, turns a *detected*
  # /dev/urandom string into a non-zero pipeline status the `if` reads as "not
  # found". Capturing the match keeps this assertion fail-closed.
  local fallback_strings
  fallback_strings="$(strings -a "$probe_binary" | grep -F '/dev/urandom' || true)"
  if [[ -n "$fallback_strings" ]]; then
    echo "  linked probe contains the /dev/urandom fallback" >&2
    return 1
  fi
}

# structural fixture: an Apple compile of trezor-crypto/crypto/rand.c
# must emit no RNG definitions at all.  This is asserted against the source
# tree, independently of CMake, so a future source-list or target change cannot
# quietly hand the weak fallback back to the linker.
assert_fallback_source_defines_nothing() {
  local library_identifier="$1"
  local architecture="$2"
  local output_dir="$3"
  local sdk_name
  local minimum_version_flag
  local fallback_object="$output_dir/rand.c.o"
  local definitions

  mkdir -p "$output_dir"
  {
    IFS= read -r sdk_name
    IFS= read -r minimum_version_flag
  } < <(platform_link_flags "$library_identifier")

  if ! xcrun --sdk "$sdk_name" clang \
    -arch "$architecture" \
    "$minimum_version_flag" \
    -I "$TREZOR_INCLUDE_DIR" \
    -c "$FALLBACK_SOURCE" \
    -o "$fallback_object"; then
    echo "  could not compile trezor rand.c for ${library_identifier}/${architecture}" >&2
    return 1
  fi

  definitions="$(nm -m "$fallback_object" \
    | grep -E '\(__TEXT,__text\) (weak )?external _(random32|random_buffer)$' || true)"
  if [[ -n "$definitions" ]]; then
    echo "  trezor rand.c still defines RNG symbols on Apple:" >&2
    printf '    %s\n' "$definitions" >&2
    return 1
  fi
}

# negative regression: with SecRandom.m.o removed there is no provider
# left anywhere in the archive, so the production-equivalent link must fail with
# unresolved RNG symbols instead of producing a runnable fallback binary.
assert_missing_provider_breaks_link() {
  local archive_path="$1"
  local library_identifier="$2"
  local architecture="$3"
  local output_dir="$4"
  local sdk_name
  local minimum_version_flag
  local negative_archive="$output_dir/WalletCore-without-SecRandom.a"
  local link_log="$output_dir/link.log"
  local remaining_definitions

  mkdir -p "$output_dir"
  cp "$archive_path" "$negative_archive"
  ar -d "$negative_archive" SecRandom.m.o
  ranlib "$negative_archive"

  # Capture rather than `grep -q`: on a multi-megabyte `nm` dump an early match
  # kills the producer with SIGPIPE, and `set -o pipefail` then reports the
  # pipeline as failed — which this `if` would read as "no definition left",
  # silently passing the exact regression the assertion exists to catch.
  remaining_definitions="$(nm -m -o "$negative_archive" \
    | grep -E '\(__TEXT,__text\) (weak )?external _(random32|random_buffer)$' || true)"
  if [[ -n "$remaining_definitions" ]]; then
    echo "  archive still defines an RNG symbol after removing SecRandom.m.o:" >&2
    printf '    %s\n' "$remaining_definitions" >&2
    return 1
  fi

  {
    IFS= read -r sdk_name
    IFS= read -r minimum_version_flag
  } < <(platform_link_flags "$library_identifier")

  if emit_probe_source | xcrun --sdk "$sdk_name" clang++ \
      -arch "$architecture" \
      "$minimum_version_flag" \
      -x c++ - \
      -x none "$negative_archive" \
      -framework Security \
      -framework CoreFoundation \
      -Wl,-dead_strip \
      -o "$output_dir/probe" >"$link_log" 2>&1; then
    echo "  production mnemonic probe still linked without SecRandom.m.o" >&2
    return 1
  fi

  if ! grep -Fq '_random_buffer' "$link_log"; then
    echo "  link failed without naming _random_buffer; unrelated failure:" >&2
    sed 's/^/    /' "$link_log" >&2
    return 1
  fi

  if ! grep -Eqi 'undefined symbol' "$link_log"; then
    echo "  link failure was not an unresolved-symbol error:" >&2
    sed 's/^/    /' "$link_log" >&2
    return 1
  fi
}

while IFS= read -r archive_path; do
  library_identifier="$(basename "$(dirname "$archive_path")")"
  architectures="$(lipo -archs "$archive_path")"

  for architecture in $architectures; do
    architecture_dir="$VERIFY_TMP_DIR/${library_identifier}-${architecture}"
    thin_archive="$architecture_dir/WalletCore.a"
    mkdir -p "$architecture_dir"

    if [[ "$architectures" == "$architecture" ]]; then
      cp "$archive_path" "$thin_archive"
    else
      lipo "$archive_path" -thin "$architecture" -output "$thin_archive"
    fi

    symbol_output="$architecture_dir/symbols.txt"
    nm -m -o "$thin_archive" > "$symbol_output"

    for symbol_name in random32 random_buffer; do
      if ! grep -Eq "SecRandom\\.m\\.o:.*\\(__TEXT,__text\\) external _${symbol_name}$" "$symbol_output"; then
        echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
        echo "  SecRandom.m.o does not strongly define _${symbol_name}" >&2
        exit 1
      fi
    done

    # No other archive member — trezor's rand.c.o above all — may define the RNG
    # symbols, otherwise the provider could be swapped out and still link.
    defining_objects="$(grep -E \
      '\(__TEXT,__text\) (weak )?external _(random32|random_buffer)$' \
      "$symbol_output" \
      | LC_ALL=C sed -E 's/^.*WalletCore\.a:([^:]+):.*$/\1/' | sort -u)"
    if [[ "$defining_objects" != "SecRandom.m.o" ]]; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  RNG symbols must be defined only by SecRandom.m.o, found:" >&2
      printf '    %s\n' "$defining_objects" >&2
      exit 1
    fi

    (
      cd "$architecture_dir"
      ar -x "$thin_archive" SecRandom.m.o
    )

    provider_object="$architecture_dir/SecRandom.m.o"
    if [[ ! -f "$provider_object" ]]; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  SecRandom.m.o is missing from the archive" >&2
      exit 1
    fi

    provider_import_check="$(nm -u "$provider_object" | grep -E '^_SecRandomCopyBytes$' || true)"
    if [[ -z "$provider_import_check" ]]; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  SecRandom.m.o does not import SecRandomCopyBytes" >&2
      exit 1
    fi

    # Capture rather than `grep -Fq`: under `set -o pipefail` an early `-q` exit
    # can SIGPIPE the producer and turn a *detected* fallback string into a
    # non-zero pipeline status this `if` would read as "not found".
    provider_fallback_strings="$(strings -a "$provider_object" \
      | grep -F '/dev/urandom' || true)"
    if [[ -n "$provider_fallback_strings" ]]; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  SecRandom.m.o contains the /dev/urandom fallback" >&2
      exit 1
    fi

    if ! assert_fallback_source_defines_nothing \
      "$library_identifier" \
      "$architecture" \
      "$architecture_dir/fallback-source"; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  trezor-crypto rand.c can still supply an Apple RNG fallback" >&2
      exit 1
    fi

    if ! assert_linked_provider \
      "$thin_archive" \
      "$library_identifier" \
      "$architecture" \
      "$architecture_dir/positive-link"; then
      echo "Apple RNG verification failed for ${library_identifier}/${architecture}:" >&2
      echo "  linked mnemonic generation did not select SecRandom.m.o" >&2
      exit 1
    fi

    # Exercise the invalid configuration once against a deterministic fixture:
    # removing the Apple provider must break the production-equivalent link
    # rather than fall back to trezor-crypto.
    if ! $negative_regression_ran; then
      if ! assert_missing_provider_breaks_link \
        "$thin_archive" \
        "$library_identifier" \
        "$architecture" \
        "$architecture_dir/negative-link"; then
        echo "Apple RNG negative regression failed for ${library_identifier}/${architecture}:" >&2
        echo "  omitting SecRandom.m.o did not fail the link" >&2
        exit 1
      fi

      echo "  ok negative regression: removing SecRandom.m.o breaks the link"
      negative_regression_ran=true
    fi

    echo "  ok ${library_identifier}/${architecture}: linked SecRandomCopyBytes provider"
    verified_architectures=$((verified_architectures + 1))
  done
done < <(find "$XCFRAMEWORK_PATH" -mindepth 2 -maxdepth 2 -type f -name '*.a' | sort)

if [[ $verified_architectures -eq 0 ]]; then
  echo "Apple RNG verification failed: no static libraries found in $XCFRAMEWORK_PATH" >&2
  exit 1
fi

if ! $negative_regression_ran; then
  echo "Apple RNG verification failed: negative link regression never ran" >&2
  exit 1
fi

echo "Verified Apple RNG provider in ${verified_architectures} architecture(s)."
