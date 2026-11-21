#include "scrypt/mac/hmac_sha256.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* RFC 4231 Test Case 1 */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    const char *data1 = "Hi There";
    const uint8_t exp1[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    uint8_t mac1[32];
    scrypt_hmac_sha256(key1, sizeof(key1), data1, strlen(data1), mac1);
    assert(memcmp(mac1, exp1, sizeof(exp1)) == 0);

    /* RFC 4231 Test Case 2 (streaming update) */
    const uint8_t key2[4] = { 'J', 'e', 'f', 'e' };
    const char *data2 = "what do ya want for nothing?";
    const uint8_t exp2[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    uint8_t mac2[32];
    scrypt_hmac_sha256_ctx ctx;
    scrypt_hmac_sha256_init(&ctx, key2, sizeof(key2));
    scrypt_hmac_sha256_update(&ctx, data2, 10u);
    scrypt_hmac_sha256_update(&ctx, data2 + 10u, strlen(data2) - 10u);
    scrypt_hmac_sha256_final(&ctx, mac2);
    assert(memcmp(mac2, exp2, sizeof(exp2)) == 0);

    /* RFC 4231 Test Case 6: key longer than 64-byte block (131 bytes of 0xaa) */
    uint8_t key6[131];
    memset(key6, 0xaa, sizeof(key6));
    const char *data6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    const uint8_t exp6[32] = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
        0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
        0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
        0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
    };

    uint8_t mac6[32];
    scrypt_hmac_sha256(key6, sizeof(key6), data6, strlen(data6), mac6);
    assert(memcmp(mac6, exp6, sizeof(exp6)) == 0);

    printf("HMAC-SHA256 RFC 4231 test cases passed.\n");
    return 0;
}
