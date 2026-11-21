#include "scrypt/aead/xchacha20_poly1305.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* draft-irtf-cfrg-xchacha Test Vector Section A.3.1 */
    const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    const uint8_t nonce24[24] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    };
    const uint8_t aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const size_t pt_len = strlen(pt);

    uint8_t ct[114] = {0};
    uint8_t tag[16] = {0};
    uint8_t dec[114] = {0};

    scrypt_xchacha20_poly1305_encrypt(key, nonce24, aad, sizeof(aad),
                                      (const uint8_t *)pt, pt_len, ct, tag);

    int rc = scrypt_xchacha20_poly1305_decrypt(key, nonce24, aad, sizeof(aad),
                                               ct, pt_len, tag, dec);
    assert(rc == SCRYPT_XCHACHA20_AEAD_OK);
    assert(memcmp(dec, pt, pt_len) == 0);

    /* Tamper check on AAD */
    uint8_t bad_aad[12];
    memcpy(bad_aad, aad, sizeof(aad));
    bad_aad[0] ^= 0xffu;
    rc = scrypt_xchacha20_poly1305_decrypt(key, nonce24, bad_aad, sizeof(bad_aad),
                                          ct, pt_len, tag, dec);
    assert(rc == SCRYPT_XCHACHA20_AEAD_ERR_AUTH);

    printf("XChaCha20-Poly1305 round-trip & tamper tests passed.\n");
    return 0;
}
