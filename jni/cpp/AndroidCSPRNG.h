// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2026 Perpetua Labs.

#pragma once

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

// Fill exactly `len` bytes from Android's kernel CSPRNG or terminate.
//
// Use the getrandom syscall directly instead of bionic's getrandom wrapper:
// the syscall is available on every supported Android kernel, while the libc
// wrapper is only available from API 28 and the native library declares API
// 26 compatibility. There is deliberately no fallback entropy provider.
static inline void android_csprng_fill_exact(uint8_t* buffer, size_t len) {
    size_t total = 0;
    while (total < len) {
        const size_t remaining = len - total;
        const size_t request = remaining > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX
            : remaining;
        const long filled = syscall(__NR_getrandom, buffer + total, request, 0);
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
