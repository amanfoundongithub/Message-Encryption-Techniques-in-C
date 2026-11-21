#include "scrypt/cipher/aes.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* FIPS 197 Appendix B test vector */
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t expected_ct[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    uint8_t ct[16] = {0};
    uint8_t pt[16] = {0};

    scrypt_aes128_ctx ctx;
    scrypt_aes128_init(&ctx, key);
    scrypt_aes128_encrypt_block(&ctx, plaintext, ct);
    scrypt_aes128_decrypt_block(&ctx, ct, pt);
    scrypt_aes128_wipe(&ctx);

    assert(memcmp(ct, expected_ct, sizeof(expected_ct)) == 0);
    assert(memcmp(pt, plaintext, sizeof(plaintext)) == 0);

    printf("AES-128 block encrypt/decrypt KAT passed.\n");
    return 0;
}
