// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

import Foundation

public extension PublicKey {
    /// Returns the ripemd160 hash of the sha2 hash of the compressed public key data.
    var bitcoinKeyHash: Data {
        return Hash.sha256RIPEMD(data: compressed.data)
    }
}
