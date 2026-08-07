// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.
//
// Android OS CSPRNG provider for WalletCore.
//
// This is the single approved entropy source for Android WalletCore. It
// replaces the former conditional provider that crossed JNI into
// java.security.SecureRandom when JNI_OnLoad happened to populate a cached
// JavaVM, and read /dev/urandom otherwise. RNG provider selection must never
// depend on native library load order or JVM attachment state, so this file
// contains no JavaVM/JNIEnv/JNI_OnLoad/SecureRandom usage and no conditional
// provider logic of any kind.
//
// Failure contract: fail closed. If the kernel CSPRNG cannot supply every
// requested byte, the process terminates. There is no deterministic,
// weaker, or partially-filled fallback — by design.
//
// Platform contract: the native library declares Android API 26 compatibility.
// Android's libc getrandom wrapper is only available from API 28, so the
// shared provider calls the kernel syscall directly. Every supported Android
// kernel implements getrandom; an unexpected ENOSYS still aborts fail closed.
// This file is compiled into Android shared-library builds only (see the
// ANDROID branch of the top-level CMakeLists.txt); Apple platforms use
// swift/Sources/SecRandom.m.
//
// Build-time provenance is enforced by tools/verify-android-rng.sh, which
// checks the retained provider object, production link map, dynamic imports,
// and negative fixtures to prove that this translation unit owns the strong
// random32/random_buffer symbols in libwallet_core.so and uses the kernel
// CSPRNG syscall path.

#include <stdint.h>

#include "AndroidCSPRNG.h"

extern "C" {
    uint32_t random32();
    void random_buffer(uint8_t *buf, size_t len);
}

uint32_t random32() {
    uint32_t result;
    android_csprng_fill_exact(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

void random_buffer(uint8_t *buf, size_t len) {
    android_csprng_fill_exact(buf, len);
}
