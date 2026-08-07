#!/usr/bin/env bash
# Verify that an Android libwallet_core.so resolves its RNG to the approved
# native getrandom-syscall provider (jni/cpp/Random.cpp) and can only fail closed
# against the kernel CSPRNG.
#
# Checks, per ABI artifact:
#   1. random32/random_buffer are strong global text (T) definitions.
#   2. The retained Random.cpp.o strongly owns both symbols, calls syscall
#      directly, and does not import the API-28 getrandom libc wrapper or JNI.
#   3. The retained production link map binds both final symbols to that object.
#   4. The linked .so imports syscall, never strongly imports the API-28
#      bionic getrandom wrapper, and does not import JNI / dlopen.
#   5. When <libwallet_core.so> lives in an `unstripped/` directory and a
#      stripped packaging copy sits at the parent path, the two artifacts must
#      share identical PT_LOAD segments (offset/vaddr/filesz/memsz/flags) —
#      proving the shipped APK/AAB copy executes the exact bytes that were
#      verified here, not a substituted binary.
#   6. Negative fixtures with the provider symbols renamed, with a same-symbol
#      wrong-syscall replacement, and with the syscall import removed must all
#      be rejected by the verifier logic itself.
#
# Usage: verify-android-rng.sh <libwallet_core.so> <ndk-llvm-toolchain-bin>
#
# VERIFY_ANDROID_PROVIDER_OBJECT and VERIFY_ANDROID_LINK_MAP must point to the
# retained per-ABI Random.cpp.o and production link map.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <libwallet_core.so> <ndk-llvm-bin-dir>" >&2
  exit 2
fi

SO_PATH="$1"
LLVM_BIN="$2"
if [[ ! -f "$SO_PATH" ]]; then
  echo "Android RNG verification failed: not found: $SO_PATH" >&2
  exit 1
fi
if [[ ! -d "$LLVM_BIN" ]]; then
  echo "Android RNG verification failed: NDK llvm bin dir not found: $LLVM_BIN" >&2
  exit 1
fi

NM="$LLVM_BIN/llvm-nm"
OBJCOPY="$LLVM_BIN/llvm-objcopy"
OBJDUMP="$LLVM_BIN/llvm-objdump"
READELF="$LLVM_BIN/llvm-readelf"
STRINGS="$LLVM_BIN/llvm-strings"
CLANGXX="$LLVM_BIN/clang++"
for tool in "$NM" "$OBJCOPY" "$OBJDUMP" "$READELF" "$STRINGS" "$CLANGXX"; do
  if [[ ! -x "$tool" ]]; then
    echo "Android RNG verification failed: missing tool: $tool" >&2
    exit 1
  fi
done

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_TOOLS_DIR="$TOOLS_DIR/android"

# The ELF helpers are standard-library-only so the mandatory Gradle gate does
# not depend on mutable environments, network access, or a particular Python
# minor version. Gradle may resolve Apple's Python rather than the interactive
# shell's Python; both must execute the same verifier.
PY_HELPER="${VERIFY_ANDROID_RNG_PYTHON:-python3}"
if ! command -v "$PY_HELPER" >/dev/null 2>&1; then
  echo "Android RNG verification failed: Python not found: $PY_HELPER" >&2
  exit 1
fi

PROVIDER_OBJECT="${VERIFY_ANDROID_PROVIDER_OBJECT:-}"
LINK_MAP="${VERIFY_ANDROID_LINK_MAP:-}"
if [[ ! -f "$PROVIDER_OBJECT" ]]; then
  echo "Android RNG verification failed: provider object missing: $PROVIDER_OBJECT" >&2
  exit 1
fi
if [[ ! -f "$LINK_MAP" ]]; then
  echo "Android RNG verification failed: production link map missing: $LINK_MAP" >&2
  exit 1
fi

fail() {
  echo "Android RNG verification failed for $(basename "$SO_PATH"):" >&2
  echo "  $1" >&2
  return 1
}

# ── Shared assertion (used for the real artifact and the negative fixture) ──
assert_artifact() {
  local so="$1"
  local nm_all nm_dyn strings_all

  # Note: the production version script localizes every non-TW* symbol, so
  # random32/random_buffer appear as local (t) text definitions in the final
  # .so — still owned by jni/cpp/Random.cpp, still resolved internally to the
  # approved provider. Localized-by-version-script is the *expected* shape;
  # provenance is proven below against the unity TU object when the build
  # tree is available.
  nm_all="$("$NM" "$so" 2>/dev/null || true)"
  nm_dyn="$("$NM" -D "$so" 2>/dev/null || true)"
  strings_all="$("$STRINGS" "$so" 2>/dev/null || true)"

  # 1. Text definitions of the approved provider entry points (strong in the
  #    provider object; localized in the final .so by the version script).
  for sym in random32 random_buffer; do
    if ! grep -Eq "[[:space:]][Tt] ${sym}\$" <<<"$nm_all"; then
      fail "libwallet_core.so does not define ${sym} (expected T/t from jni/cpp/Random.cpp)"
      return 1
    fi
    if grep -Eq "[[:space:]][Ww] ${sym}\$" <<<"$nm_all"; then
      fail "libwallet_core.so has a WEAK ${sym} definition — the trezor fallback won the link"
      return 1
    fi
  done

  # 1b. The weak trezor-crypto /dev/urandom fallback must not be the live
  #     provider: exactly one text definition per entry point.
  for sym in random32 random_buffer; do
    local defs
    defs="$(grep -Ec "[[:space:]][Tt] ${sym}\$" <<<"$nm_all" || true)"
    if [[ "$defs" -ne 1 ]]; then
      fail "expected exactly 1 text definition of ${sym}, found ${defs}"
      return 1
    fi
  done

  # The provider uses the raw getrandom syscall so API 26/27 do not depend on
  # bionic's API-28 getrandom wrapper. The final artifact must resolve syscall.
  if ! grep -Eq "[[:space:]]U syscall(@.*)?\$" <<<"$nm_dyn"; then
    echo "Android RNG verification failed for $(basename "$SO_PATH"):" >&2
    echo "  libwallet_core.so does not dynamically import syscall" >&2
    return 1
  fi

  # A *strong* getrandom import would reintroduce the API-28 libc floor on a
  # library that declares API 26 support: the loader cannot resolve it on
  # Android 8.x. The Rust runtime's weak (w) getrandom reference is fine —
  # it resolves to 0 and is not the wallet entropy path.
  if grep -Eq "[[:space:]]U getrandom(@.*)?\$" <<<"$nm_dyn"; then
    echo "Android RNG verification failed for $(basename "$SO_PATH"):" >&2
    echo "  libwallet_core.so strongly imports the bionic getrandom wrapper" >&2
    echo "  (API 28+); the provider must use the raw syscall" >&2
    return 1
  fi

  # 2/4. No JNI-based RNG bridge may survive in the artifact. Match any nm
  #      record rather than only undefined imports: a reintroduced JNI_OnLoad
  #      would be a *defined* (T) symbol, which a "U "-anchored pattern misses.
  for jni_sym in JNI_GetCreatedJavaVMs JNI_OnLoad AttachCurrentThread; do
    if grep -Eq "[[:space:]]_?${jni_sym}\$" <<<"$nm_all" \
       || grep -Eq "[[:space:]]_?${jni_sym}\$" <<<"$nm_dyn"; then
      fail "libwallet_core.so references ${jni_sym} (JNI RNG bridge must be gone)"
      return 1
    fi
  done
  if grep -Eqi "cachedJVM|SecureRandom|java/security/SecureRandom" \
      <<<"${nm_all}"$'\n'"${strings_all}"; then
    fail "libwallet_core.so contains the removed JNI SecureRandom provider"
    return 1
  fi

  # 5. The .so may not dynamically import dlopen for entropy: the provider
  #    is a direct getrandom call, not a runtime-loaded bridge. (dlsym is
  #    used by the Rust/C++ runtime for unrelated address lookups and is not
  #    an entropy path; the JNI-entropy symbols are rejected above.)
  if grep -Eq "[[:space:]]U dlopen(@.*)?\$" <<<"$nm_all" \
     || grep -Eq "[[:space:]]U dlopen(@.*)?\$" <<<"$nm_dyn"; then
    fail "libwallet_core.so imports dlopen"
    return 1
  fi

  # 6. The .so's only entropy-source imports are the kernel CSPRNG. The
  #    Rust runtime (std::sys::random) may also resolve getrandom internally
  #    — that is fine and expected; what is forbidden is any JNI or
  #    Java-layer entropy path, checked above.
}

# ── Provenance: prove the approved translation unit owns the symbols ───────
assert_provider_object() {
  local provider="$1" nm_obj strings_obj machine disassembly relocations
  nm_obj="$("$NM" "$provider" 2>/dev/null || true)"
  strings_obj="$("$STRINGS" "$provider" 2>/dev/null || true)"
  # Extraction, not a `grep -q`-style search: `awk` (like the `sed -nE 's///p'`
  # it replaced) reads the producer to EOF, so neither form can SIGPIPE
  # llvm-readelf under `set -o pipefail`. This site is fail-closed either way —
  # a failed pipeline aborts the assignment under `set -e`, and an empty
  # `machine` falls through to the `*)` arm below. `awk` is kept only because
  # one tool doing both the match and the strip is easier to audit.
  machine="$("$READELF" -h "$provider" 2>/dev/null \
    | awk '/Machine:/ { sub(/^[[:space:]]*Machine:[[:space:]]*/, ""); print }')"
  disassembly="$("$OBJDUMP" -d --no-show-raw-insn "$provider" 2>/dev/null || true)"
  relocations="$("$READELF" -r "$provider" 2>/dev/null || true)"
  for sym in random32 random_buffer; do
    if ! grep -Eq "[[:space:]]T ${sym}\$" <<<"$nm_obj"; then
      fail "retained Random.cpp.o does not strongly define ${sym}"
      return 1
    fi
  done
  if ! grep -Eq "[[:space:]]U syscall\$" <<<"$nm_obj"; then
    fail "retained Random.cpp.o does not call the getrandom syscall path"
    return 1
  fi
  if grep -Eq "[[:space:]]U getrandom\$" <<<"$nm_obj"; then
    fail "retained Random.cpp.o imports bionic getrandom (unavailable before API 28)"
    return 1
  fi
  if ! grep -Eq "[[:space:]]U abort\$" <<<"$nm_obj"; then
    fail "retained Random.cpp.o does not retain the fail-closed abort path"
    return 1
  fi
  if grep -Eqi "AttachCurrentThread|JNI_GetCreatedJavaVMs|JNI_OnLoad" <<<"$nm_obj"; then
    fail "retained Random.cpp.o references JNI entropy machinery"
    return 1
  fi
  if grep -Eqi "SecureRandom|java/security|/dev/urandom" <<<"$strings_obj"; then
    fail "retained Random.cpp.o contains a forbidden Java or device-file entropy path"
    return 1
  fi

  # An undefined `syscall` symbol alone does not prove which syscall is made.
  # Prove both entry points load the ABI's getrandom number, pass flags=0,
  # retry EINTR, and retain the two fail-closed abort edges (OS/zero-or-overfill).
  local getrandom_pattern flags_pattern errno_pattern
  case "$machine" in
    AArch64)
      getrandom_pattern='mov[[:space:]]+w0, #0x116'
      flags_pattern='mov[[:space:]]+w3, wzr'
      errno_pattern='cmp[[:space:]]+w[0-9]+, #0x4'
      ;;
    ARM)
      getrandom_pattern='mov\.w[[:space:]]+r0, #0x180'
      flags_pattern='movs[[:space:]]+r3, #0x0'
      errno_pattern='cmp[[:space:]]+r[0-9]+, #0x4'
      ;;
    *)
      fail "retained Random.cpp.o has unsupported machine type: ${machine:-unknown}"
      return 1
      ;;
  esac

  local function_name function_body relocation_block abort_relocations
  for function_name in random32 random_buffer; do
    function_body="$(awk -v marker="<${function_name}>:" '
      index($0, marker) { capture = 1; next }
      capture && /^Disassembly of section / { exit }
      capture { print }
    ' <<<"$disassembly")"
    if [[ -z "$function_body" ]]; then
      fail "retained Random.cpp.o has no disassembly for ${function_name}"
      return 1
    fi
    if [[ "$(grep -Ec "$getrandom_pattern" <<<"$function_body" || true)" -ne 1 ]]; then
      fail "${function_name} does not load the ${machine} getrandom syscall number exactly once"
      return 1
    fi
    if [[ "$(grep -Ec "$flags_pattern" <<<"$function_body" || true)" -ne 1 ]]; then
      fail "${function_name} does not pass getrandom flags=0 exactly once"
      return 1
    fi
    if ! grep -Eq "$errno_pattern" <<<"$function_body"; then
      fail "${function_name} does not retain the EINTR retry check"
      return 1
    fi

    relocation_block="$(awk -v section=".text.${function_name}" '
      /^Relocation section / { capture = index($0, section) > 0; next }
      capture && NF == 0 { exit }
      capture { print }
    ' <<<"$relocations")"
    if [[ "$(grep -Ec '[[:space:]]syscall([[:space:]]|[+]0|$)' \
        <<<"$relocation_block" || true)" -ne 1 ]]; then
      fail "${function_name} does not relocate exactly one call to syscall"
      return 1
    fi
    abort_relocations="$(grep -Ec '[[:space:]]abort([[:space:]]|[+]0|$)' \
      <<<"$relocation_block" || true)"
    if [[ "$abort_relocations" -lt 2 ]]; then
      fail "${function_name} does not retain both fail-closed abort edges"
      return 1
    fi
  done
}

assert_link_map_ownership() {
  local object_name
  object_name="$(basename "$PROVIDER_OBJECT")"
  if ! grep -Fq "$object_name" "$LINK_MAP"; then
    fail "production link map does not include $object_name"
    return 1
  fi
  for sym in random32 random_buffer; do
    if ! awk -v object="$object_name" -v symbol="$sym" '
      index($0, object) { window = 12 }
      window > 0 && $NF == symbol { found = 1 }
      window > 0 { window-- }
      END { exit(found ? 0 : 1) }
    ' "$LINK_MAP"; then
      fail "production link map does not bind ${sym} to ${object_name}"
      return 1
    fi
  done
}

assert_provenance() {
  assert_provider_object "$PROVIDER_OBJECT"
  assert_link_map_ownership
  echo "  ok provenance: Random.cpp.o owns linked random32/random_buffer"
}

# ── Packaging-copy equivalence ─────────────────────────────────────────────
# When SO_PATH is the verified unstripped artifact and a stripped packaging
# copy exists alongside it (jniLibs/<abi>/libwallet_core.so), prove the two
# share identical PT_LOAD segments: the segment headers (offset, vaddr,
# filesz, memsz, flags) and the bytes backing them. Stripping removes only
# section-table symbol info, so equal LOAD segments mean the shipped binary
# executes exactly the code that was verified above.
assert_packaging_equivalence() {
  local parent_dir base stripped
  parent_dir="$(dirname "$SO_PATH")"
  base="$(basename "$parent_dir")"
  [[ "$base" == "unstripped" ]] || return 0
  stripped="$(dirname "$parent_dir")/$(basename "$SO_PATH")"
  if [[ ! -f "$stripped" ]]; then
    fail "stripped packaging copy is missing: $stripped"
    return 1
  fi

  local segs_a segs_b
  segs_a="$("$PY_HELPER" "$ANDROID_TOOLS_DIR/load-segments.py" "$SO_PATH")"
  segs_b="$("$PY_HELPER" "$ANDROID_TOOLS_DIR/load-segments.py" "$stripped")"
  if [[ -z "$segs_a" ]]; then
    fail "could not read PT_LOAD segments from $SO_PATH"
    return 1
  fi
  if [[ "$segs_a" != "$segs_b" ]]; then
    fail "stripped packaging copy $(basename "$stripped") LOAD segments differ from the verified artifact — refusing to trust the shipped binary"
    return 1
  fi
  echo "  ok packaging copy $(basename "$stripped"): LOAD segments identical to verified artifact"
}

# ── Positive verification of the real artifact ─────────────────────────────
assert_artifact "$SO_PATH"
assert_provenance
assert_packaging_equivalence

echo "  ok $(basename "$SO_PATH"): fail-closed getrandom syscall provider"

# ── Negative fixtures ───────────────────────────────────────────────────────
# Removing the intended provider symbols must make the provenance verifier
# reject the retained object.
NEG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/android-rng-negative.XXXXXX")"
trap 'rm -rf "$NEG_DIR"' EXIT

NEG_OBJECT="$NEG_DIR/Random.cpp.o"
cp "$PROVIDER_OBJECT" "$NEG_OBJECT"
"$OBJCOPY" \
  --redefine-sym random32=removed_random32 \
  --redefine-sym random_buffer=removed_random_buffer \
  "$NEG_OBJECT"
if assert_provider_object "$NEG_OBJECT" >"$NEG_DIR/negative-object.log" 2>&1; then
  fail "negative regression: verifier accepted a replacement provider object"
fi
echo "  ok negative regression: replacement provider object is rejected"

# A replacement object can keep the approved symbol names and import both
# syscall and abort while quietly invoking the wrong syscall. Compile that
# regression for the current ABI; the instruction/relocation proof above must
# reject it instead of mistaking "calls some syscall" for "uses getrandom".
NEG_REPLACEMENT_SOURCE="$NEG_DIR/Random-replacement.cpp"
NEG_REPLACEMENT_OBJECT="$NEG_DIR/Random-replacement.o"
cat >"$NEG_REPLACEMENT_SOURCE" <<'CPP'
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline void replacement_fill(uint8_t* buffer, size_t len) {
    size_t total = 0;
    while (total < len) {
        const size_t remaining = len - total;
        const size_t request = remaining > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX
            : remaining;
        const long filled = syscall(__NR_getpid, buffer + total, request, 0);
        if (filled < 0) {
            if (errno == EINTR) {
                continue;
            }
            abort();
        }
        if (filled == 0 || (unsigned long)filled > request) {
            abort();
        }
        total += (size_t)filled;
    }
}

extern "C" uint32_t random32(void) {
    uint32_t result;
    replacement_fill(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}
extern "C" void random_buffer(uint8_t* buffer, size_t len) {
    replacement_fill(buffer, len);
}
CPP
# Same extraction as assert_provider_object, and fail-closed for the same
# reason: `awk` reads llvm-readelf to EOF (no SIGPIPE under pipefail), and an
# empty result lands on the `*)` arm, which calls `fail`.
case "$("$READELF" -h "$PROVIDER_OBJECT" \
    | awk '/Machine:/ { sub(/^[[:space:]]*Machine:[[:space:]]*/, ""); print }')" in
  AArch64) negative_target="aarch64-linux-android26" ;;
  ARM) negative_target="armv7a-linux-androideabi26" ;;
  *) fail "negative replacement fixture has unsupported provider ABI" ;;
esac
"$CLANGXX" --target="$negative_target" -fPIC -O2 -ffunction-sections \
  -c "$NEG_REPLACEMENT_SOURCE" -o "$NEG_REPLACEMENT_OBJECT"
if assert_provider_object "$NEG_REPLACEMENT_OBJECT" \
    >"$NEG_DIR/negative-replacement.log" 2>&1; then
  fail "negative regression: verifier accepted a same-symbol wrong-syscall provider"
fi
if ! grep -Eq 'does not load the (AArch64|ARM) getrandom syscall number exactly once' \
    "$NEG_DIR/negative-replacement.log"; then
  sed 's/^/  fixture: /' "$NEG_DIR/negative-replacement.log" >&2
  fail "negative regression setup did not reach the getrandom syscall-number check"
fi
echo "  ok negative regression: same-symbol wrong-syscall provider is rejected"

# Removing the provider's syscall dependency must also make the linked-artifact
# verifier reject the binary.
NEG_SO="$NEG_DIR/libwallet_core-no-syscall.so"
cp "$SO_PATH" "$NEG_SO"

# Remove the undefined syscall dynamic symbol from the copy. The artifact
# is otherwise untouched; the verifier must now reject it. llvm-objcopy
# cannot edit .dynstr entries, so the removal uses the in-repo ELF helper.
REMOVE_DYNSYM="$ANDROID_TOOLS_DIR/remove-dynsym.py"
if [[ ! -f "$REMOVE_DYNSYM" ]]; then
  fail "negative fixture helper missing: $REMOVE_DYNSYM"
fi
"$PY_HELPER" "$REMOVE_DYNSYM" "$NEG_SO" syscall >/dev/null

# Capture rather than `grep -q`: on a large `nm -D` dump an early `-q` exit can
# SIGPIPE the producer, and `set -o pipefail` then reports the pipeline as
# failed — which this `if` would read as "import removed", silently passing the
# exact regression the fixture exists to catch. Reading the whole stream keeps
# the check fail-closed.
syscall_import_check="$("$NM" -D "$NEG_SO" 2>/dev/null \
  | grep -E "[[:space:]]U syscall(@.*)?\$" || true)"
if [[ -n "$syscall_import_check" ]]; then
  fail "negative fixture setup failed: could not remove the syscall dynamic import"
fi
if assert_artifact "$NEG_SO" >"$NEG_DIR/negative.log" 2>&1; then
  fail "negative regression: verifier accepted an artifact with no syscall import"
fi
echo "  ok negative regression: artifact without syscall import is rejected"

echo "Verified Android RNG provider in $(basename "$SO_PATH")."
