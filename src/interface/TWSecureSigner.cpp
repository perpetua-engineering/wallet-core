// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.
// Copyright © 2024 Perpetua Labs.
//
// Secure Enclave-integrated signing implementation.

#include <TrustWalletCore/TWSecureSigner.h>
#include <TrustWalletCore/TWData.h>

#if !defined(__APPLE__)

// Stub implementations for non-Apple platforms
TWData* _Nonnull TWSecureSignerSignEthereum(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignBitcoin(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignSolana(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignUtxo(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, enum TWCoinType, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignTron(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignXrp(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignDigest(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, enum TWCoinType, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWData* _Nonnull TWSecureSignerSignEd25519(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, TWData* _Nonnull, TWString* _Nonnull) {
    return TWDataCreateWithSize(0);
}
TWString* _Nonnull TWSecureSignerDeriveAddress(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull, enum TWCoinType, TWString* _Nonnull) {
    return TWStringCreateWithUTF8Bytes("");
}
TWData* _Nullable TWSecureSignerDeriveSeed(
    TWData* _Nonnull, const void* _Nonnull, TWString* _Nonnull) {
    return nullptr;
}
void TWSecureSignerFreeSeed(TWData* _Nonnull seed) {
    if (seed) TWDataDelete(seed);
}
TWData* _Nullable TWSecureSignerCreateWallet(
    const void* _Nonnull, TWString* _Nonnull) {
    return nullptr;
}

#else // __APPLE__

#include <TrustWalletCore/TWData.h>
#include <TrustWalletCore/TWString.h>

#include "Data.h"
#include "HDWallet.h"
#include "DerivationPath.h"
#include "Coin.h"
#include "HexCoding.h"
#include "PrivateKey.h"
#include "Mnemonic.h"

#include "proto/Ethereum.pb.h"
#include "proto/Bitcoin.pb.h"
#include "proto/Solana.pb.h"
#include "proto/Tron.pb.h"
#include "proto/Ripple.pb.h"

// C headers need extern "C" to prevent C++ name mangling
extern "C" {
#include <TrezorCrypto/memzero.h>
#include <TrezorCrypto/hmac.h>
#include <TrezorCrypto/sha2.h>
#include <TrezorCrypto/chacha20poly1305/rfc7539.h>
#include <TrezorCrypto/chacha20poly1305/chacha20poly1305.h>
#include <TrezorCrypto/ecdsa.h>
#include <TrezorCrypto/nist256p1.h>
}

#include <Security/Security.h>
#include <string>
#include <vector>
#include <array>

using namespace TW;

namespace {

// HKDF-SHA256 Extract: PRK = HMAC-Hash(salt, IKM)
void hkdfExtract(const uint8_t* salt, size_t saltLen,
                 const uint8_t* ikm, size_t ikmLen,
                 uint8_t prk[32]) {
    if (saltLen == 0) {
        // RFC 5869: If salt is empty, use HashLen zeros
        uint8_t zeros[32] = {0};
        hmac_sha256(zeros, 32, ikm, (uint32_t)ikmLen, prk);
    } else {
        hmac_sha256(salt, (uint32_t)saltLen, ikm, (uint32_t)ikmLen, prk);
    }
}

// HKDF-SHA256 Expand: OKM = HKDF-Expand(PRK, info, L)
void hkdfExpand(const uint8_t prk[32],
                const uint8_t* info, size_t infoLen,
                uint8_t* okm, size_t okmLen) {
    uint8_t t[32] = {0};
    size_t tLen = 0;
    uint8_t counter = 1;
    size_t offset = 0;

    while (offset < okmLen) {
        HMAC_SHA256_CTX ctx;
        hmac_sha256_Init(&ctx, prk, 32);
        if (tLen > 0) {
            hmac_sha256_Update(&ctx, t, (uint32_t)tLen);
        }
        if (infoLen > 0) {
            hmac_sha256_Update(&ctx, info, (uint32_t)infoLen);
        }
        hmac_sha256_Update(&ctx, &counter, 1);
        hmac_sha256_Final(&ctx, t);
        tLen = 32;

        size_t copyLen = (okmLen - offset < 32) ? (okmLen - offset) : 32;
        memcpy(okm + offset, t, copyLen);
        offset += copyLen;
        counter++;
    }

    memzero(t, sizeof(t));
}

// HKDF-SHA256: Full operation
void hkdfSha256(const uint8_t* salt, size_t saltLen,
                const uint8_t* ikm, size_t ikmLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* okm, size_t okmLen) {
    uint8_t prk[32];
    hkdfExtract(salt, saltLen, ikm, ikmLen, prk);
    hkdfExpand(prk, info, infoLen, okm, okmLen);
    memzero(prk, sizeof(prk));
}

// Perform ECDH with Secure Enclave key
bool performECDH(SecKeyRef seKey, const uint8_t* ephemeralPubX963, size_t pubLen,
                 uint8_t sharedSecret[32]) {
    // Create SecKey from ephemeral public key data
    CFDataRef pubKeyData = CFDataCreate(kCFAllocatorDefault, ephemeralPubX963, pubLen);
    if (!pubKeyData) return false;

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);

    CFErrorRef error = nullptr;
    SecKeyRef ephemeralPubKey = SecKeyCreateWithData(pubKeyData, attrs, &error);
    CFRelease(pubKeyData);
    CFRelease(attrs);

    if (!ephemeralPubKey) {
        if (error) CFRelease(error);
        return false;
    }

    // Perform ECDH key exchange
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDataRef sharedSecretData = SecKeyCopyKeyExchangeResult(
        seKey, kSecKeyAlgorithmECDHKeyExchangeStandard, ephemeralPubKey, params, &error);

    CFRelease(ephemeralPubKey);
    CFRelease(params);

    if (!sharedSecretData) {
        if (error) CFRelease(error);
        return false;
    }

    // Copy shared secret (should be 32 bytes for P-256)
    CFIndex secretLen = CFDataGetLength(sharedSecretData);
    if (secretLen < 32) {
        CFRelease(sharedSecretData);
        return false;
    }

    memcpy(sharedSecret, CFDataGetBytePtr(sharedSecretData), 32);
    CFRelease(sharedSecretData);
    return true;
}

// Decrypt mnemonic using SE key
// Format: version(1) + ephemeralPub(65) + nonce(12) + ciphertext + tag(16)
bool decryptMnemonic(const Data& encrypted, SecKeyRef seKey, const std::string& salt, std::string& mnemonic) {
    if (encrypted.size() < 1 + 65 + 12 + 16) {
        return false;
    }

    uint8_t version = encrypted[0];

    if (version == 0x00) {
        // Unencrypted - just copy
        mnemonic = std::string(encrypted.begin() + 1, encrypted.end());
        return true;
    }

    if (version != 0x01) {
        return false;  // Unknown version
    }

    // Parse encrypted blob
    const uint8_t* ephemeralPub = encrypted.data() + 1;       // 65 bytes X9.63
    const uint8_t* nonce = encrypted.data() + 66;             // 12 bytes
    const uint8_t* ciphertext = encrypted.data() + 78;        // variable
    size_t ciphertextLen = encrypted.size() - 78 - 16;
    const uint8_t* tag = encrypted.data() + encrypted.size() - 16;  // 16 bytes

    // Perform ECDH: SE private + ephemeral public
    uint8_t sharedSecret[32];
    if (!performECDH(seKey, ephemeralPub, 65, sharedSecret)) {
        return false;
    }

    // HKDF-SHA256 to derive symmetric key
    uint8_t symmetricKey[32];
    hkdfSha256(
        (const uint8_t*)salt.data(), salt.size(),
        sharedSecret, 32,
        nullptr, 0,  // No info
        symmetricKey, 32
    );
    memzero(sharedSecret, sizeof(sharedSecret));

    // Decrypt with ChaCha20-Poly1305 (RFC 7539)
    std::vector<uint8_t> plaintext(ciphertextLen);

    chacha20poly1305_ctx ctx;
    rfc7539_init(&ctx, symmetricKey, nonce);
    chacha20poly1305_decrypt(&ctx, ciphertext, plaintext.data(), ciphertextLen);

    // Verify tag
    // NOTE: chacha20poly1305_decrypt already feeds ciphertext to Poly1305 internally.
    // Do NOT call rfc7539_auth here — that would double-feed and corrupt the tag.
    uint8_t computedTag[16];
    rfc7539_finish(&ctx, 0, ciphertextLen, computedTag);

    memzero(symmetricKey, sizeof(symmetricKey));
    memzero(&ctx, sizeof(ctx));

    // Constant-time tag comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computedTag[i] ^ tag[i];
    }

    if (diff != 0) {
        memzero(plaintext.data(), plaintext.size());
        return false;  // Authentication failed
    }

    mnemonic = std::string(plaintext.begin(), plaintext.end());
    memzero(plaintext.data(), plaintext.size());

    return true;
}

// Encrypt mnemonic using SE key
// Returns blob: version(1) + ephemeralPub(65) + nonce(12) + ciphertext + tag(16)
// Returns empty Data on failure.
Data encryptMnemonic(const std::string& mnemonic, SecKeyRef seKey, const std::string& salt) {
    // Get SE public key
    SecKeyRef sePubKey = SecKeyCopyPublicKey(seKey);
    if (!sePubKey) {
        return {};
    }

    // Generate ephemeral P-256 key pair (software, not SE)
    CFMutableDictionaryRef ephAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int keySize = 256;
    CFNumberRef keySizeRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySize);
    CFDictionarySetValue(ephAttrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(ephAttrs, kSecAttrKeySizeInBits, keySizeRef);

    CFErrorRef error = nullptr;
    SecKeyRef ephPrivKey = SecKeyCreateRandomKey(ephAttrs, &error);
    CFRelease(keySizeRef);
    CFRelease(ephAttrs);

    if (!ephPrivKey) {
        if (error) CFRelease(error);
        CFRelease(sePubKey);
        return {};
    }

    // Get ephemeral public key in X9.63 format (65 bytes for P-256)
    SecKeyRef ephPubKey = SecKeyCopyPublicKey(ephPrivKey);
    if (!ephPubKey) {
        CFRelease(ephPrivKey);
        CFRelease(sePubKey);
        return {};
    }

    CFErrorRef pubError = nullptr;
    CFDataRef ephPubData = SecKeyCopyExternalRepresentation(ephPubKey, &pubError);
    CFRelease(ephPubKey);

    if (!ephPubData) {
        if (pubError) CFRelease(pubError);
        CFRelease(ephPrivKey);
        CFRelease(sePubKey);
        return {};
    }

    size_t ephPubLen = (size_t)CFDataGetLength(ephPubData);
    if (ephPubLen != 65) {
        CFRelease(ephPubData);
        CFRelease(ephPrivKey);
        CFRelease(sePubKey);
        return {};
    }

    // ECDH: ephemeral private × SE public → shared secret
    uint8_t sharedSecret[32];
    {
        CFMutableDictionaryRef params = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFErrorRef ecdhError = nullptr;
        CFDataRef secretData = SecKeyCopyKeyExchangeResult(
            ephPrivKey, kSecKeyAlgorithmECDHKeyExchangeStandard, sePubKey, params, &ecdhError);
        CFRelease(params);
        CFRelease(ephPrivKey);
        CFRelease(sePubKey);

        if (!secretData) {
            if (ecdhError) CFRelease(ecdhError);
            CFRelease(ephPubData);
            return {};
        }

        CFIndex secretLen = CFDataGetLength(secretData);
        if (secretLen < 32) {
            CFRelease(secretData);
            CFRelease(ephPubData);
            return {};
        }

        memcpy(sharedSecret, CFDataGetBytePtr(secretData), 32);
        CFRelease(secretData);
    }

    // HKDF-SHA256: shared secret + salt → symmetric key
    uint8_t symmetricKey[32];
    hkdfSha256(
        (const uint8_t*)salt.data(), salt.size(),
        sharedSecret, 32,
        nullptr, 0,
        symmetricKey, 32
    );
    memzero(sharedSecret, sizeof(sharedSecret));

    // Generate 12-byte random nonce
    uint8_t nonce[12];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce) != errSecSuccess) {
        memzero(symmetricKey, sizeof(symmetricKey));
        CFRelease(ephPubData);
        return {};
    }

    // ChaCha20-Poly1305 encrypt
    size_t plaintextLen = mnemonic.size();
    std::vector<uint8_t> ciphertext(plaintextLen);

    chacha20poly1305_ctx ctx;
    rfc7539_init(&ctx, symmetricKey, nonce);
    chacha20poly1305_encrypt(&ctx, (const uint8_t*)mnemonic.data(), ciphertext.data(), plaintextLen);

    uint8_t tag[16];
    rfc7539_finish(&ctx, 0, plaintextLen, tag);

    memzero(symmetricKey, sizeof(symmetricKey));
    memzero(&ctx, sizeof(ctx));

    // Build output blob: version(1) + ephemeralPub(65) + nonce(12) + ciphertext + tag(16)
    Data result;
    result.reserve(1 + 65 + 12 + plaintextLen + 16);
    result.push_back(0x01); // version
    const uint8_t* pubBytes = CFDataGetBytePtr(ephPubData);
    result.insert(result.end(), pubBytes, pubBytes + 65);
    result.insert(result.end(), nonce, nonce + 12);
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag, tag + 16);

    CFRelease(ephPubData);
    memzero(ciphertext.data(), ciphertext.size());

    return result;
}

// Derive private key from mnemonic and path
std::optional<PrivateKey> deriveKey(const std::string& mnemonic, const std::string& path, TWCoinType coin) {
    try {
        HDWallet<> wallet(mnemonic, "");
        DerivationPath derivationPath(path);
        return wallet.getKey(coin, derivationPath);
    } catch (...) {
        return std::nullopt;
    }
}

} // anonymous namespace

// --- Public API ---

TWData* _Nonnull TWSecureSignerSignEthereum(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeEthereum);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Ethereum::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.set_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(TWCoinTypeEthereum, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignBitcoin(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeBitcoin);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Bitcoin::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.add_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(TWCoinTypeBitcoin, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignSolana(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeSolana);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Solana::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.set_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(TWCoinTypeSolana, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignUtxo(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    enum TWCoinType coin,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, coin);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Bitcoin::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.add_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(coin, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignTron(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeTron);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Tron::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.set_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(TWCoinTypeTron, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignXrp(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull unsignedTx,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& txData = *reinterpret_cast<const Data*>(unsignedTx);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeXRP);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Parse signing input and inject private key
    Ripple::Proto::SigningInput input;
    if (!input.ParseFromArray(txData.data(), (int)txData.size())) {
        return TWDataCreateWithSize(0);
    }

    input.set_private_key(privateKey.bytes.data(), privateKey.bytes.size());

    // Sign
    Data inputData(input.ByteSizeLong());
    input.SerializeToArray(inputData.data(), (int)inputData.size());

    Data outputData;
    TW::anyCoinSign(TWCoinTypeXRP, inputData, outputData);

    // Clear private key from protobuf
    input.clear_private_key();

    return TWDataCreateWithBytes(outputData.data(), outputData.size());
}

TWData* _Nonnull TWSecureSignerSignDigest(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull digest,
    enum TWCoinType coin,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& digestData = *reinterpret_cast<const Data*>(digest);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    if (digestData.size() != 32) {
        return TWDataCreateWithSize(0);
    }

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, coin);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Sign the digest with secp256k1 (for Ethereum-compatible chains)
    auto signature = privateKey.sign(digestData, TWCurveSECP256k1);

    return TWDataCreateWithBytes(signature.data(), signature.size());
}

TWData* _Nonnull TWSecureSignerSignEd25519(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    TWData* _Nonnull message,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const Data& messageData = *reinterpret_cast<const Data*>(message);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWDataCreateWithSize(0);
    }

    // Derive key (Solana uses Ed25519)
    auto privateKeyOpt = deriveKey(mnemonic, path, TWCoinTypeSolana);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWDataCreateWithSize(0);
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Sign with Ed25519 (handles arbitrary-length messages, internal SHA-512)
    Data signature = privateKey.sign(messageData, TWCurveED25519);

    return TWDataCreateWithBytes(signature.data(), signature.size());
}

TWString* _Nonnull TWSecureSignerDeriveAddress(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull derivationPath,
    enum TWCoinType coinType,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& path = *reinterpret_cast<const std::string*>(derivationPath);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return TWStringCreateWithUTF8Bytes("");
    }

    // Derive key
    auto privateKeyOpt = deriveKey(mnemonic, path, coinType);
    memzero(mnemonic.data(), mnemonic.size());
    if (!privateKeyOpt) {
        return TWStringCreateWithUTF8Bytes("");
    }
    PrivateKey& privateKey = *privateKeyOpt;

    // Derive address
    std::string address = TW::deriveAddress(coinType, privateKey);

    return TWStringCreateWithUTF8Bytes(address.c_str());
}

TWData* _Nullable TWSecureSignerDeriveSeed(
    TWData* _Nonnull encryptedMnemonic,
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt
) {
    const Data& encrypted = *reinterpret_cast<const Data*>(encryptedMnemonic);
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Decrypt mnemonic
    std::string mnemonic;
    if (!decryptMnemonic(encrypted, seKey, salt, mnemonic)) {
        return nullptr;
    }

    // Derive seed
    try {
        HDWallet<> wallet(mnemonic, "");
        memzero(mnemonic.data(), mnemonic.size());

        const auto& seed = wallet.getSeed();
        TWData* result = TWDataCreateWithBytes(seed.data(), seed.size());
        // HDWallet destructor zeros seed and mnemonic internally
        return result;
    } catch (...) {
        memzero(mnemonic.data(), mnemonic.size());
        return nullptr;
    }
}

void TWSecureSignerFreeSeed(TWData* _Nonnull seed) {
    if (!seed) return;
    // TWData is const void* — we need to zero the underlying Data
    auto* data = const_cast<Data*>(reinterpret_cast<const Data*>(seed));
    memzero(data->data(), data->size());
    TWDataDelete(seed);
}

TWData* _Nullable TWSecureSignerCreateWallet(
    const void* _Nonnull seKeyRef,
    TWString* _Nonnull hkdfSalt
) {
    const std::string& salt = *reinterpret_cast<const std::string*>(hkdfSalt);
    SecKeyRef seKey = (SecKeyRef)seKeyRef;

    // Generate a 256-bit (24-word) mnemonic
    std::string mnemonic;
    try {
        HDWallet<> wallet(256, "");
        mnemonic = wallet.getMnemonic();
    } catch (...) {
        return nullptr;
    }

    // Validate the generated mnemonic
    if (!Mnemonic::isValid(mnemonic)) {
        memzero(mnemonic.data(), mnemonic.size());
        return nullptr;
    }

    // SE-encrypt the mnemonic — Swift never sees plaintext
    Data encrypted = encryptMnemonic(mnemonic, seKey, salt);
    memzero(mnemonic.data(), mnemonic.size());

    if (encrypted.empty()) {
        return nullptr;
    }

    return TWDataCreateWithBytes(encrypted.data(), encrypted.size());
}

#endif // __APPLE__
