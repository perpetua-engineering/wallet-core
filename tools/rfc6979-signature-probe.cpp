// Public fake vector used to prove the final WalletCore artifact's ECDSA mode.
// This file is linked against the shipped archive/shared library; it does not
// compile a second copy of ecdsa.c.

#include <TWData.h>
#include <TWPrivateKey.h>
#include <TWPublicKey.h>

#include <array>
#include <cstdio>
#include <cstring>

extern "C" int TWCryptographRFC6979Mode(void);

namespace {

constexpr std::array<uint8_t, 32> privateKey = {
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
    0x46,
};

constexpr std::array<uint8_t, 32> digest = {
    0x22,
    0x3f,
    0x88,
    0x07,
    0x55,
    0x67,
    0x8a,
    0x9c,
    0x12,
    0x51,
    0x2b,
    0x9a,
    0x44,
    0x3d,
    0x62,
    0xb3,
    0x79,
    0x0e,
    0x54,
    0x94,
    0xf4,
    0x69,
    0x23,
    0xf2,
    0x03,
    0x7d,
    0x88,
    0xaf,
    0x7f,
    0x50,
    0x23,
    0x1a,
};

// 64-byte compact signature followed by WalletCore's recovery byte.
constexpr std::array<uint8_t, 65> expectedSignature = {
    0xf6,
    0xd0,
    0xd8,
    0x58,
    0x64,
    0x67,
    0xb2,
    0x9d,
    0x6e,
    0x32,
    0x16,
    0x28,
    0xff,
    0xe1,
    0xd4,
    0xf7,
    0x20,
    0x2f,
    0xa9,
    0xb9,
    0xcf,
    0x9a,
    0x2b,
    0xa6,
    0xe8,
    0xe0,
    0x57,
    0x93,
    0xb4,
    0x02,
    0xc0,
    0xdd,
    0x39,
    0xc1,
    0x30,
    0x6d,
    0x3d,
    0xe3,
    0xe7,
    0xec,
    0x49,
    0x43,
    0xc1,
    0xa3,
    0x33,
    0x08,
    0xbc,
    0x41,
    0xbe,
    0x38,
    0x1b,
    0x7c,
    0xed,
    0xc5,
    0xcd,
    0x0c,
    0x70,
    0x5b,
    0x36,
    0xba,
    0xd0,
    0xa3,
    0xf0,
    0x76,
    0x00,
};

int fail(int code, const char* message) {
    std::fprintf(stderr, "RFC6979 artifact probe failed: %s\n", message);
    return code;
}

} // namespace

int main() {
    if (TWCryptographRFC6979Mode() != 1) {
        return fail(10, "artifact does not attest USE_RFC6979=1");
    }

    TWData* keyData = TWDataCreateWithBytes(privateKey.data(), privateKey.size());
    TWData* digestData = TWDataCreateWithBytes(digest.data(), digest.size());
    TWPrivateKey* key = TWPrivateKeyCreateWithData(keyData);
    if (key == nullptr) {
        TWDataDelete(digestData);
        TWDataDelete(keyData);
        return fail(11, "fixed private key was rejected");
    }

    TWPublicKey* publicKey = TWPrivateKeyGetPublicKeySecp256k1(key, true);
    int result = 0;
    for (int iteration = 0; iteration < 8; ++iteration) {
        TWData* signature = TWPrivateKeySign(key, digestData, TWCurveSECP256k1);
        if (signature == nullptr) {
            result = fail(12, "signing returned null");
            break;
        }
        if (TWDataSize(signature) != expectedSignature.size() ||
            std::memcmp(
                TWDataBytes(signature),
                expectedSignature.data(),
                expectedSignature.size()) != 0) {
            result = fail(13, "signature differs from the RFC6979 known answer");
            TWDataDelete(signature);
            break;
        }
        if (!TWPublicKeyVerify(publicKey, signature, digestData)) {
            result = fail(14, "signature verification failed");
            TWDataDelete(signature);
            break;
        }
        TWDataDelete(signature);
    }

    TWPublicKeyDelete(publicKey);
    TWPrivateKeyDelete(key);
    TWDataDelete(digestData);
    TWDataDelete(keyData);

    if (result == 0) {
        std::puts("RFC6979 artifact probe passed");
    }
    return result;
}
