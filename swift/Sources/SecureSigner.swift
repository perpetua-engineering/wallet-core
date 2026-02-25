// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.
// Copyright © 2024 Perpetua Labs.
//
// Swift wrapper for Secure Enclave-integrated signing.
// Performs decryption, key derivation, and signing entirely in C++
// with guaranteed memory zeroing.

#if canImport(Security)
import Foundation
import Security

/// Secure signer that performs SE decryption, key derivation, and signing
/// entirely in C++ with guaranteed memory zeroing.
///
/// This API eliminates Swift memory copies of sensitive data (mnemonic, private keys)
/// that cannot be securely erased due to Swift's copy-on-write semantics.
///
/// Apple platforms only (iOS, watchOS, macOS).
public enum SecureSigner {

    /// Signs an Ethereum transaction using SE-encrypted mnemonic.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob (version + ephemeralPub + nonce + ciphertext + tag)
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/60'/0'/0/0")
    ///   - unsignedTx: Serialized EthereumSigningInput protobuf (without private key)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signEthereum(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignEthereum(mnemonicPtr, keyPtr, pathPtr, txPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs a Bitcoin transaction using SE-encrypted mnemonic.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/84'/0'/0'/0/0")
    ///   - unsignedTx: Serialized BitcoinSigningInput protobuf (without private key)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signBitcoin(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignBitcoin(mnemonicPtr, keyPtr, pathPtr, txPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs a Solana transaction using SE-encrypted mnemonic.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/501'/0'/0'")
    ///   - unsignedTx: Serialized SolanaSigningInput protobuf (without private key)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signSolana(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignSolana(mnemonicPtr, keyPtr, pathPtr, txPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs a UTXO transaction for any Bitcoin-family chain (BTC, LTC, DOGE, etc.).
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/3'/0'/0/0" for DOGE)
    ///   - unsignedTx: Serialized BitcoinSigningInput protobuf (without private key)
    ///   - coin: Coin type (.bitcoin, .litecoin, .dogecoin, etc.)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signUtxo(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        coin: CoinType,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignUtxo(
            mnemonicPtr,
            keyPtr,
            pathPtr,
            txPtr,
            TWCoinType(rawValue: coin.rawValue),
            saltPtr
        )

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs a Tron transaction using SE-encrypted mnemonic.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/195'/0'/0/0")
    ///   - unsignedTx: Serialized TronSigningInput protobuf (without private key)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signTron(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignTron(mnemonicPtr, keyPtr, pathPtr, txPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs an XRP transaction using SE-encrypted mnemonic.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/144'/0'/0/0")
    ///   - unsignedTx: Serialized RippleSigningInput protobuf (without private key)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Signed transaction bytes, or empty Data on error
    public static func signXrp(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        unsignedTx: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let txPtr = TWDataCreateWithNSData(unsignedTx)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignXrp(mnemonicPtr, keyPtr, pathPtr, txPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(txPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs a raw message digest using SE-encrypted mnemonic.
    ///
    /// Use for personal_sign, eth_sign, signTypedData after hashing.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path
    ///   - digest: 32-byte message digest to sign
    ///   - coin: Coin type (determines curve)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: 65-byte signature (r + s + v), or empty Data on error
    public static func signDigest(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        digest: Data,
        coin: CoinType,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let digestPtr = TWDataCreateWithNSData(digest)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignDigest(
            mnemonicPtr,
            keyPtr,
            pathPtr,
            digestPtr,
            TWCoinType(rawValue: coin.rawValue),
            saltPtr
        )

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(digestPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Signs arbitrary message bytes with Ed25519 using SE-encrypted mnemonic.
    /// For Solana WalletConnect: signTransaction (message portion) and signMessage.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/501'/0'/0/0")
    ///   - message: Arbitrary-length message bytes to sign
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: 64-byte Ed25519 signature, or empty Data on error
    public static func signEd25519(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        message: Data,
        hkdfSalt: String
    ) -> Data {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let msgPtr = TWDataCreateWithNSData(message)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerSignEd25519(mnemonicPtr, keyPtr, pathPtr, msgPtr, saltPtr)

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWDataDelete(msgPtr)
        TWStringDelete(saltPtr)

        return TWDataNSData(result)
    }

    /// Generates a new 24-word wallet entirely in C++ and returns the SE-encrypted mnemonic blob.
    /// The mnemonic is generated, validated, encrypted, and zeroed — Swift never sees plaintext.
    ///
    /// - Parameters:
    ///   - seKey: Secure Enclave private key for ECDH encryption
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match decryption salt)
    /// - Returns: SE-encrypted mnemonic blob, or nil on error
    public static func createWallet(
        seKey: SecKey,
        hkdfSalt: String
    ) -> Data? {
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerCreateWallet(keyPtr, saltPtr)

        TWStringDelete(saltPtr)

        guard let result else { return nil }
        return TWDataNSData(result)
    }

    /// Imports a user-provided seed phrase: validates, SE-encrypts, zeroes the plaintext.
    /// Swift never sees the mnemonic after this call returns.
    ///
    /// - Parameters:
    ///   - mnemonic: BIP-39 mnemonic string (12 or 24 words)
    ///   - seKey: Secure Enclave private key for ECDH encryption
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match decryption salt)
    /// - Returns: SE-encrypted mnemonic blob, or nil if invalid mnemonic or error
    public static func importSeedPhrase(
        mnemonic: String,
        seKey: SecKey,
        hkdfSalt: String
    ) -> Data? {
        let mnemonicPtr = TWStringCreateWithNSString(mnemonic)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerImportSeedPhrase(mnemonicPtr, keyPtr, saltPtr)

        TWStringDelete(mnemonicPtr)
        TWStringDelete(saltPtr)

        guard let result else { return nil }
        return TWDataNSData(result)
    }

    /// Decrypts a CGREC recovery payload, validates the mnemonic, and SE-encrypts it.
    /// Performs PBKDF2-HMAC-SHA256 key derivation with progress reporting, then
    /// ChaCha20-Poly1305 decryption, BIP-39 validation, and SE encryption.
    /// The plaintext mnemonic never enters Swift memory.
    ///
    /// - Parameters:
    ///   - pbkdf2Salt: PBKDF2 salt from the recovery payload (16 bytes)
    ///   - nonce: ChaCha20-Poly1305 nonce (12 bytes)
    ///   - ciphertext: Ciphertext + Poly1305 tag (tag is last 16 bytes)
    ///   - iterations: PBKDF2 iteration count (100,000..10,000,000)
    ///   - payloadVersion: CGREC payload version byte (for AAD construction)
    ///   - secret: Normalized secret (PIN digits or lowercased passphrase)
    ///   - pepper: Optional session binding pepper (23 bytes), nil if pepperVersion < 1
    ///   - serial: Optional serial string for AAD binding
    ///   - seKey: Secure Enclave private key for ECDH encryption
    ///   - hkdfSalt: Domain separator for SE HKDF key derivation (must match decryption salt)
    ///   - progress: Optional callback for KDF progress (0.0 to 1.0)
    /// - Returns: SE-encrypted mnemonic blob, or nil on error (wrong PIN, invalid mnemonic, etc.)
    public static func importRecovery(
        pbkdf2Salt: Data,
        nonce: Data,
        ciphertext: Data,
        iterations: UInt32,
        payloadVersion: UInt8,
        secret: String,
        pepper: Data?,
        serial: String?,
        seKey: SecKey,
        hkdfSalt: String,
        progress: ((Double) -> Void)? = nil
    ) -> Data? {
        let saltPtr = TWDataCreateWithNSData(pbkdf2Salt)
        let noncePtr = TWDataCreateWithNSData(nonce)
        let ctPtr = TWDataCreateWithNSData(ciphertext)
        let secretPtr = TWStringCreateWithNSString(secret)
        let hkdfSaltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let serialTWStr = serial.map { TWStringCreateWithNSString($0) }

        // Copy pepper into a contiguous array so the pointer stays valid
        let pepperBytes: [UInt8] = pepper.map { Array($0) } ?? []

        // Bridge the Swift progress closure to a C function pointer via context
        var progressClosure = progress

        // Bridge the Swift progress closure to a C function pointer via context.
        // withUnsafeMutablePointer keeps closurePtr alive for the duration of the call.
        let cCallback: TWSecureSignerProgressCallback?
        if progress != nil {
            cCallback = { (p: Double, rawCtx: UnsafeRawPointer?) in
                guard let rawCtx else { return }
                let ptr = rawCtx.assumingMemoryBound(to: Optional<(Double) -> Void>.self)
                ptr.pointee?(p)
            }
        } else {
            cCallback = nil
        }

        let result = withUnsafeMutablePointer(to: &progressClosure) { closurePtr in
            pepperBytes.withUnsafeBufferPointer { pepperBuf in
                TWSecureSignerImportRecovery(
                    saltPtr,
                    noncePtr,
                    ctPtr,
                    iterations,
                    payloadVersion,
                    secretPtr,
                    pepperBuf.isEmpty ? nil : pepperBuf.baseAddress,
                    pepperBuf.count,
                    serialTWStr,
                    keyPtr,
                    hkdfSaltPtr,
                    cCallback,
                    progress != nil ? UnsafeMutableRawPointer(closurePtr) : nil
                )
            }
        }

        TWDataDelete(saltPtr)
        TWDataDelete(noncePtr)
        TWDataDelete(ctPtr)
        TWStringDelete(secretPtr)
        TWStringDelete(hkdfSaltPtr)
        if let serialTWStr {
            TWStringDelete(serialTWStr)
        }

        guard let result else { return nil }
        return TWDataNSData(result)
    }

    /// Derives an address for any supported chain using SE-encrypted mnemonic.
    /// Decrypts mnemonic, derives key, formats address, zeros all intermediates.
    ///
    /// - Parameters:
    ///   - encryptedMnemonic: SE-encrypted mnemonic blob
    ///   - seKey: Secure Enclave private key for ECDH decryption
    ///   - derivationPath: BIP44 derivation path (e.g., "m/44'/60'/0'/0/0")
    ///   - coin: Coin type (determines curve and address format)
    ///   - hkdfSalt: Domain separator for HKDF key derivation (must match encryption salt)
    /// - Returns: Address string, or nil on error
    public static func deriveAddress(
        encryptedMnemonic: Data,
        seKey: SecKey,
        derivationPath: String,
        coin: CoinType,
        hkdfSalt: String
    ) -> String? {
        let mnemonicPtr = TWDataCreateWithNSData(encryptedMnemonic)
        let pathPtr = TWStringCreateWithNSString(derivationPath)
        let saltPtr = TWStringCreateWithNSString(hkdfSalt)
        let keyPtr = Unmanaged.passUnretained(seKey).toOpaque()

        let result = TWSecureSignerDeriveAddress(
            mnemonicPtr,
            keyPtr,
            pathPtr,
            TWCoinType(rawValue: coin.rawValue),
            saltPtr
        )

        TWDataDelete(mnemonicPtr)
        TWStringDelete(pathPtr)
        TWStringDelete(saltPtr)

        let address = TWStringNSString(result)
        return address.isEmpty ? nil : address
    }
}
#endif
