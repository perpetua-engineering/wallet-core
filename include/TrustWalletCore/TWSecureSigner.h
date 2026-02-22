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

TW_EXTERN_C_END
