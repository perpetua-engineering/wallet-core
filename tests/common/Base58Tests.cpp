// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include "Base58.h"

#include <gtest/gtest.h>

namespace TW::Base58::tests {

TEST(Base58, DecodeNullEmbedded) {
    const auto valid = std::string("1Bp9U1ogV3A14FMvKbRJms7ctyso5FdSz2");

    const auto withJunk = valid + '\0' + "garbage";
    EXPECT_TRUE(decodeCheck(withJunk).empty());

    const auto trailingNul = valid + '\0';
    EXPECT_TRUE(decodeCheck(trailingNul).empty());
}

} // namespace TW::Base58::tests
