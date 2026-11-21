#include "scrypt/kdf/hkdf_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* RFC 5869 Test Case 1 (SHA-256) */
    uint8_t ikm1[22];
    memset(ikm1, 0x0b, sizeof(ikm1));
    const uint8_t salt1[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t info1[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    const uint8_t exp_okm1[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t okm1[42] = {0};
    int rc = scrypt_hkdf_sha256(salt1, sizeof(salt1), ikm1, sizeof(ikm1),
                              info1, sizeof(info1), okm1, sizeof(okm1));
    assert(rc == SCRYPT_HKDF_OK);
    assert(memcmp(okm1, exp_okm1, sizeof(exp_okm1)) == 0);

    /* Reject overly long output (> 255 * 32 bytes) */
    uint8_t dummy[1];
    assert(scrypt_hkdf_sha256_expand(okm1, NULL, 0u, dummy, SCRYPT_HKDF_SHA256_MAX_OKM + 1u) == SCRYPT_HKDF_ERR_PARAM);

    printf("HKDF-SHA256 RFC 5869 test passed.\n");
    return 0;
}
