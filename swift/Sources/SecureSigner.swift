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
