#include "scrypt/aead/aes_gcm.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* NIST SP 800-38D Test Case 2 (AES-128-GCM, 96-bit IV, 16-byte PT, empty AAD) */
    const uint8_t key128[16] = {0};
    const uint8_t iv96[12] = {0};
    const uint8_t pt16[16] = {0};
    const uint8_t exp_ct128[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    const uint8_t exp_tag128[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };

    uint8_t ct128[16] = {0};
    uint8_t tag128[16] = {0};
    uint8_t dec128[16] = {0};

    int rc = scrypt_aes128_gcm_encrypt(key128, iv96, sizeof(iv96), NULL, 0u,
                                     pt16, sizeof(pt16), ct128, tag128);
    assert(rc == SCRYPT_GCM_OK);
    assert(memcmp(ct128, exp_ct128, 16u) == 0);
    assert(memcmp(tag128, exp_tag128, 16u) == 0);

    rc = scrypt_aes128_gcm_decrypt(key128, iv96, sizeof(iv96), NULL, 0u,
                                   ct128, sizeof(ct128), tag128, dec128);
    assert(rc == SCRYPT_GCM_OK);
    assert(memcmp(dec128, pt16, 16u) == 0);

    /* Tamper check + AES-256-GCM round-trip with non-12-byte IV & AAD */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag128, 16u);
    bad_tag[15] ^= 0x01u;
    assert(scrypt_aes128_gcm_decrypt(key128, iv96, sizeof(iv96), NULL, 0u,
                                   ct128, sizeof(ct128), bad_tag, dec128) == SCRYPT_GCM_ERR_AUTH);

    const uint8_t key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t iv16[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    const uint8_t aad[8] = { 'h', 'e', 'a', 'd', 'e', 'r', '0', '1' };
    const uint8_t msg[25] = "Authenticated GCM payload";
    uint8_t ct256[25] = {0};
    uint8_t tag256[16] = {0};
    uint8_t dec256[25] = {0};

    assert(scrypt_aes256_gcm_encrypt(key256, iv16, sizeof(iv16), aad, sizeof(aad),
                                   msg, sizeof(msg), ct256, tag256) == SCRYPT_GCM_OK);
    assert(scrypt_aes256_gcm_decrypt(key256, iv16, sizeof(iv16), aad, sizeof(aad),
                                   ct256, sizeof(ct256), tag256, dec256) == SCRYPT_GCM_OK);
    assert(memcmp(dec256, msg, sizeof(msg)) == 0);

    printf("AES-128-GCM and AES-256-GCM tests passed.\n");
    return 0;
}
