#include "scrypt/cipher/des.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const uint8_t key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
    };
    const uint8_t plaintext[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    const uint8_t expected_ct[8] = {
        0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05
    };

    uint8_t ct[8] = {0};
    uint8_t pt[8] = {0};

    scrypt_des_ctx ctx;
    scrypt_des_init(&ctx, key);
    scrypt_des_encrypt_block(&ctx, plaintext, ct);
    scrypt_des_decrypt_block(&ctx, ct, pt);
    scrypt_des_wipe(&ctx);

    assert(memcmp(ct, expected_ct, sizeof(expected_ct)) == 0);
    assert(memcmp(pt, plaintext, sizeof(plaintext)) == 0);

    printf("DES block encrypt/decrypt KAT passed.\n");
    return 0;
}