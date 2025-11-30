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
