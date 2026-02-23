# Repository Guidelines

## Project Structure & Module Organization
- Core C++ sources live in `src/`, public headers in `include/`, and crypto primitives in `trezor-crypto/`.
- Tests use GoogleTest in `tests/` (per-chain suites under `tests/chains/`); shared helpers live in `tests/common/`.
- Platform bindings: `android/` + `jni/`, `kotlin/`, `swift/`, `wasm/`, and `rust/` targets; samples in `samples/` and build scripts in `tools/`.
- Generated artifacts and local toolchains sit under `build/` (created by CMake-driven scripts); keep the tree clean in commits.

## Build, Test, and Development Commands
- Bootstrap dependencies and generate code: `./bootstrap.sh [wasm|android|ios]`.
- Full native build + tests: `tools/build-and-test [gtest_filter]` (runs CMake with clang, builds `tests` and `TrezorCryptoTests`, then executes them).
- Incremental build: `cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ && make -Cbuild -j$(nproc)`.
- Lint touched C++ files: `tools/lint` (clang-tidy; expects `build/compile_commands.json`).
- Platform targets: `tools/android-build`, `tools/ios-build`, `tools/kotlin-build`, `tools/wasm-build`; pass platform SDK env vars as needed.
- Coverage update: run lcov, then `tools/check-coverage coverage.stats coverage.info` before raising the threshold.
- Apple XCFramework flow (iOS/watchOS/macOS): `tools/build-apple.sh` generates code (Rust/cbindgen + protos), builds per-SDK slices (ios device/sim, watch device/sim, macOS arm64/x86_64), and packages `build/WalletCore.xcframework`. Use `tools/xcframework-only.sh` to repackage without rebuilding slices. Tunables: `IOS_MIN`, `WATCH_MIN`, `MAC_MIN`, `JOBS`, `SKIP_CODEGEN`, `SKIP_XCODEGEN`.
- **Agent note**: `build-apple.sh` produces ~67K lines / 7MB of output (cmake config, compile progress, third-party warnings). Pipe to a file to avoid context overflow: `JOBS=8 tools/build-apple.sh > /tmp/wallet-core-build.log 2>&1`. Check exit code and grep the log afterward.

## Coding Style & Naming Conventions
- Use clang and C++20; follow existing patterns: 4-space indentation, brace on the same line for definitions, PascalCase types, camelCase methods/functions, and snake_case locals where present.
- Keep SPDX/Apache 2.0 headers on source files; prefer `Data`/`std::array` over raw pointers.
- Generated protobufs and Swift/Kotlin bindings come from `tools/generate-files`; do not hand-edit generated code.

## Testing Guidelines
- Add GoogleTest cases under `tests/chains/<Chain>/` or `tests/common/`; name files `*Tests.cpp` and use descriptive `TEST`/`TEST_F` names.
- Run `tools/build-and-test` locally; filter with `tools/build-and-test Bitcoin` or `build/tests/tests --gtest_filter="*Bitcoin*"` when iterating.
- For coverage-sensitive changes, refresh lcov data and keep `coverage.stats` from regressing.

## Commit & Pull Request Guidelines
- Follow the existing Conventional Commit style seen in history (`feat(scope): ...`, `fix(scope): ...`), and reference issues/PRs with `#1234` when applicable.
- Keep commits focused and buildable; avoid committing generated artifacts from `build/`.
- PRs should include a brief summary, testing commands/results, affected platforms, and screenshots/logs for platform UI changes.
- Link to relevant docs (e.g., `developer.trustwallet.com/wallet-core/newblockchain`) when adding chains or protocol support.

## Security & Configuration Notes
- Never commit secrets or private keys; use test vectors under `tests/chains/.../data/` instead.
- If touching cryptography or transaction serialization, note audit impact (`audit/`) and add explicit test vectors.
- Use `SECURITY.MD` for vulnerability reporting guidance; disclose sensitive issues privately.
- Apple build specifics: module map now exports the C API (umbrella `TrustWalletCore`) with a C++ `Rust` submodule; macOS slice is fat-lipo'd as `libWalletCore-macos-universal.a` to satisfy XCFramework naming. Swift overlay requires importing upstream Swift sources (`swift/Sources`) plus a shim target re-exporting `SwiftProtobuf` as `WalletCoreSwiftProtobuf`.

## TWSecureSigner (Apple-only Secure Enclave Integration)

### Overview
`TWSecureSigner` provides signing APIs that accept encrypted mnemonic + SE key reference, performing decryption and signing entirely in C++ with deterministic memory zeroing via `memzero()`. This eliminates Swift memory copies of sensitive data.

### Files
- `include/TrustWalletCore/TWSecureSigner.h` — C API header (manually maintained, not auto-generated)
- `src/interface/TWSecureSigner.cpp` — Implementation with `#if __APPLE__` guards
- `swift/Sources/SecureSigner.swift` — Swift wrapper (manually maintained)
- `codegen/lib/templates/swift/TrustWalletCore.h.erb` — Updated to include `TWSecureSigner.h` for Apple platforms

### API Surface

| C function | Swift wrapper | Purpose |
|---|---|---|
| `TWSecureSignerSignEthereum` | `SecureSigner.signEthereum(...)` | ETH + all EVM chains |
| `TWSecureSignerSignBitcoin` | `SecureSigner.signBitcoin(...)` | BTC only |
| `TWSecureSignerSignUtxo` | `SecureSigner.signUtxo(..., coin:)` | Generic UTXO: BTC, DOGE, LTC, etc. |
| `TWSecureSignerSignSolana` | `SecureSigner.signSolana(...)` | SOL |
| `TWSecureSignerSignTron` | `SecureSigner.signTron(...)` | TRX |
| `TWSecureSignerSignXrp` | `SecureSigner.signXrp(...)` | XRP |
| `TWSecureSignerSignDigest` | `SecureSigner.signDigest(..., coin:)` | Raw 32-byte digest (secp256k1, 65-byte r+s+v) |
| `TWSecureSignerSignEd25519` | `SecureSigner.signEd25519(...)` | Ed25519 message signing (64-byte sig, arbitrary-length input) |
| `TWSecureSignerDeriveAddress` | `SecureSigner.deriveAddress(..., coin:)` | Address derivation for any chain |
| `TWSecureSignerDeriveSeed` | **None — C FFI only** | 64-byte BIP-39 seed for zcash-signer Rust FFI |
| `TWSecureSignerFreeSeed` | **None — C FFI only** | memzero + free seed from DeriveSeed |

All signing/address methods share the same SE decryption preamble: ECDH → HKDF-SHA256 → ChaCha20-Poly1305 → memzero all intermediates.

`DeriveSeed`/`FreeSeed` have no Swift wrapper by design — the seed must never reach Swift memory. These exist solely for zcash-signer's `zsig_pczt_sign_secure()` to call via C FFI.

### C/C++ Linkage
TrezorCrypto headers are pure C. When including from C++ files, wrap in `extern "C"`:
```cpp
extern "C" {
#include <TrezorCrypto/memzero.h>
#include <TrezorCrypto/chacha20poly1305/rfc7539.h>
#include <TrezorCrypto/chacha20poly1305/chacha20poly1305.h>
// ... other C headers
}
```
Without this, the linker will fail with "declaration possibly missing 'extern "C"'" errors.

### Encryption Format (v1)
The encrypted mnemonic blob format (created by Swift's `SEMnemonicEncryption`):
```
version(1) + ephemeralPubKey(65, X9.63) + nonce(12) + ciphertext + tag(16)
```
- Version `0x00`: unencrypted (SE unavailable at storage time)
- Version `0x01`: SE-encrypted with ECDH + HKDF-SHA256 + ChaCha20-Poly1305

### Build Notes
- TWSecureSigner is compiled into all Apple platform slices (iOS, watchOS, macOS)
- Non-Apple builds get stub implementations returning empty data
- After modifying, rebuild with `JOBS=8 tools/build-apple.sh` and sync to WalletCoreSPM
