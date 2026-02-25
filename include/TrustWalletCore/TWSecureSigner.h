// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.
// Copyright © 2024 Perpetua Labs.
//
// Secure Enclave-integrated signing: decrypts mnemonic and signs in C++
// with deterministic memory zeroing. Designed for iOS/watchOS.
//
// NOTE: This API is Apple-only. The seKeyRef parameter is a SecKeyRef
// cast to const void*. Swift callers should use:
//   Unmanaged.passUnretained(secKey).toOpaque()

#pragma once

#include "TWBase.h"
#include "TWData.h"
#include "TWString.h"
#include "TWCoinType.h"

TW_EXTERN_C_BEGIN

/// Secure signer that performs SE decryption, key derivation, and signing
/// entirely in C++ with guaranteed memory zeroing.
/// Apple platforms only (iOS, watchOS, macOS).
TW_EXPORT_STRUCT
struct TWSecureSigner;

/// Sign an Ethereum transaction using SE-encrypted mnemonic.
/// Decrypts mnemonic in C++, derives key, signs, zeros all sensitive data.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob (version + ephemeral pub + nonce + ciphertext + tag)
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/60'/0'/0/0")
/// \param unsignedTx Serialized EthereumSigningInput protobuf (without private key)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignEthereum(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
);

/// Sign a Bitcoin transaction using SE-encrypted mnemonic.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/84'/0'/0'/0/0")
/// \param unsignedTx Serialized BitcoinSigningInput protobuf (without private key)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignBitcoin(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
);

/// Sign a Solana transaction using SE-encrypted mnemonic.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/501'/0'/0/0")
/// \param unsignedTx Serialized SolanaSigningInput protobuf (without private key)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignSolana(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
);

/// Sign a UTXO transaction for any Bitcoin-family chain (BTC, LTC, DOGE, etc.).
/// Uses Bitcoin::Proto::SigningInput with the specified coin type for derivation and signing.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/3'/0'/0/0" for DOGE)
/// \param unsignedTx Serialized BitcoinSigningInput protobuf (without private key)
/// \param coin Coin type (TWCoinTypeBitcoin, TWCoinTypeLitecoin, TWCoinTypeDogecoin, etc.)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignUtxo(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    enum TWCoinType coin,
    TWString* _Nonnull hkdfSalt
);

/// Sign a Tron transaction using SE-encrypted mnemonic.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/195'/0'/0/0")
/// \param unsignedTx Serialized TronSigningInput protobuf (without private key)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignTron(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
);

/// Sign an XRP transaction using SE-encrypted mnemonic.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/144'/0'/0/0")
/// \param unsignedTx Serialized RippleSigningInput protobuf (without private key)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Signed transaction bytes, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignXrp(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
);

/// Sign a raw message digest using SE-encrypted mnemonic.
/// Use for personal_sign, eth_sign, signTypedData after hashing.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path
/// \param digest 32-byte message digest to sign
/// \param coin Coin type (determines curve)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns 65-byte signature (r + s + v), or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignDigest(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull digest,
    enum TWCoinType coin,
    TWString* _Nonnull hkdfSalt
);

/// Sign arbitrary message bytes with Ed25519 using SE-encrypted mnemonic.
/// For Solana WalletConnect: signTransaction (sign message portion) and signMessage.
/// Ed25519 performs its own internal SHA-512 hashing — input is the full message, not a hash.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/501'/0'/0/0")
/// \param message Arbitrary-length message bytes to sign
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns 64-byte Ed25519 signature, or empty data on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nonnull TWSecureSignerSignEd25519(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull message,
    TWString* _Nonnull hkdfSalt
);

/// Derive an address for any supported chain using SE-encrypted mnemonic.
/// Decrypts mnemonic in C++, derives key, formats address, zeros all intermediates.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param derivationPath BIP44 derivation path (e.g., "m/44'/60'/0'/0/0")
/// \param coinType Coin type (determines curve and address format)
/// \param hkdfSalt Domain separator for HKDF key derivation (e.g., "com.example.app.mnemonic.v1")
/// \returns Address string, or empty string on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWString* _Nonnull TWSecureSignerDeriveAddress(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    enum TWCoinType coinType,
    TWString* _Nonnull hkdfSalt
);

/// Decrypts SE-encrypted mnemonic and derives 64-byte BIP-39 seed.
/// For use by zcash-signer's Rust FFI only — no Swift wrapper.
/// Caller MUST call TWSecureSignerFreeSeed() to zero + free the buffer.
/// The mnemonic is zeroed internally before this function returns.
///
/// \param encryptedMnemonic SE-encrypted mnemonic blob
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param hkdfSalt Domain separator for HKDF key derivation
/// \returns 64-byte seed as TWData, or nullptr on error/non-Apple.
TW_EXPORT_STATIC_METHOD
TWData* _Nullable TWSecureSignerDeriveSeed(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt
);

/// Zeros and frees a seed buffer returned by TWSecureSignerDeriveSeed.
/// Guarantees memzero before deallocation.
///
/// \param seed TWData returned by TWSecureSignerDeriveSeed
TW_EXPORT_STATIC_METHOD
void TWSecureSignerFreeSeed(TWData* _Nonnull seed);

/// Generate a new 24-word wallet entirely in C++ and return SE-encrypted mnemonic blob.
/// The mnemonic is generated, validated, SE-encrypted, and zeroed — Swift never sees plaintext.
///
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param hkdfSalt Domain separator for HKDF key derivation (must match decryption salt)
/// \returns SE-encrypted mnemonic blob (version + ephemeralPub + nonce + ciphertext + tag),
///          or nullptr on error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nullable TWSecureSignerCreateWallet(
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt
);

/// Import a user-provided seed phrase: validate, SE-encrypt, zero the plaintext.
/// Swift never sees the mnemonic after this call returns.
///
/// \param mnemonic BIP-39 mnemonic string (12 or 24 words)
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param hkdfSalt Domain separator for HKDF key derivation (must match decryption salt)
/// \returns SE-encrypted mnemonic blob, or nullptr if invalid/error/non-Apple. Caller must delete.
TW_EXPORT_STATIC_METHOD
TWData* _Nullable TWSecureSignerImportSeedPhrase(
    TWString* _Nonnull mnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt
);

/// Progress callback for long-running KDF operations (PBKDF2).
/// Called periodically with progress from 0.0 to 1.0.
/// The context pointer is passed through from the caller.
typedef void (*TWSecureSignerProgressCallback)(double progress, const void* _Nullable context);

/// Decrypt a CGREC recovery payload, validate the mnemonic, and SE-encrypt it.
/// Performs PBKDF2-HMAC-SHA256 key derivation with progress reporting, then
/// ChaCha20-Poly1305 decryption, mnemonic validation, and SE encryption.
/// All sensitive intermediates (derived key, plaintext mnemonic) are zeroed.
///
/// Swift parses the CBOR envelope and passes raw crypto fields — no CBOR in C++.
///
/// \param pbkdf2Salt PBKDF2 salt from the recovery payload (16 bytes)
/// \param nonce ChaCha20-Poly1305 nonce (12 bytes)
/// \param ciphertext Ciphertext + Poly1305 tag (tag is last 16 bytes)
/// \param iterations PBKDF2 iteration count (100,000..10,000,000)
/// \param payloadVersion CGREC payload version byte (for AAD construction)
/// \param secret Normalized secret (PIN digits or lowercased passphrase), UTF-8
/// \param pepper Optional session binding pepper (23 bytes), or NULL if pepperVersion < 1
/// \param pepperLen Length of pepper (0 if NULL)
/// \param serial Optional serial string included in AAD when non-NULL (all versions)
/// \param seKeyRef SecKeyRef cast to void* (Apple platforms only)
/// \param hkdfSalt Domain separator for SE HKDF key derivation (must match decryption salt)
/// \param progressCallback Optional callback for KDF progress, or NULL
/// \param callbackContext Opaque pointer passed to progressCallback
/// \returns SE-encrypted mnemonic blob, or nullptr on error (wrong PIN, invalid mnemonic, etc.)
TW_EXPORT_STATIC_METHOD
TWData* _Nullable TWSecureSignerImportRecovery(
    TWData* _Nonnull pbkdf2Salt,
    TWData* _Nonnull nonce,
    TWData* _Nonnull ciphertext,
    uint32_t iterations,
    uint8_t payloadVersion,
    TWString* _Nonnull secret,
    const uint8_t* _Nullable pepper,
    size_t pepperLen,
    TWString* _Nullable serial,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt,
    TWSecureSignerProgressCallback _Nullable progressCallback,
    const void* _Nullable callbackContext
);

TW_EXTERN_C_END
