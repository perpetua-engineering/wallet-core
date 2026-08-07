/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <TrezorCrypto/rand.h>

// [cryptograph] Apple builds must not carry an RNG fallback here.
//
// On Apple platforms the one and only provider is swift/Sources/SecRandom.m,
// which is backed by SecRandomCopyBytes. When this file also emitted weak
// /dev/urandom definitions, dropping SecRandom.m from the build still produced
// a linkable archive: the weak symbols silently satisfied random32 /
// random_buffer and only a post-link verifier could catch the regression.
//
// Compiling no definitions at all on Apple makes that configuration
// unrepresentable — omitting the provider is now an unresolved-symbol link
// error instead of a runnable artifact. The guard lives in the source rather
// than in CMake so a future source-list or target change cannot reintroduce
// the fallback. Non-Apple platforms (Android and other native targets) keep
// the fail-closed fallback below; see docs/audits/walletcore-2026-06-13.md.
#if defined(__APPLE__)

// Intentionally empty: see swift/Sources/SecRandom.m.

#else

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// [wallet-core]
uint32_t __attribute__((weak)) random32(void) {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0) {
        abort();  // Critical: cannot proceed without random source
    }

    uint32_t result;
    ssize_t readLen = read(randomData, &result, sizeof(result));
    close(randomData);
    if (readLen != sizeof(result)) {
        abort();  // Critical: failed to read random data
    }

    return result;
}

void __attribute__((weak)) random_buffer(uint8_t *buf, size_t len) {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0) {
        abort();  // Critical: cannot proceed without random source
    }
    ssize_t readLen = read(randomData, buf, len);
    close(randomData);
    if (readLen != (ssize_t)len) {
        abort();  // Critical: failed to read random data
    }
}

#endif  // !__APPLE__
