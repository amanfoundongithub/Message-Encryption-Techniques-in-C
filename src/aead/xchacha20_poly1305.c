#include "scrypt/aead/xchacha20_poly1305.h"
#include "scrypt/cipher/chacha20.h"

#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static int ct_verify16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0u;
    for (size_t i = 0u; i < 16u; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return (diff == 0u) ? 0 : -1;
}

/* Construct 12-byte nonce for subkey: 4 zero bytes + nonce24[16..23] */
static void build_subnonce12(const uint8_t nonce24[24], uint8_t nonce12[12]) {
    nonce12[0] = 0u;
    nonce12[1] = 0u;
    nonce12[2] = 0u;
    nonce12[3] = 0u;
    memcpy(nonce12 + 4u, nonce24 + 16u, 8u);
}

static void derive_otk(const uint8_t subkey[32], const uint8_t nonce12[12], uint8_t otk[32]) {
    uint8_t block0[64];
    scrypt_chacha20_ctx ctx;
    scrypt_chacha20_init(&ctx, subkey, 0u, nonce12);
    scrypt_chacha20_block(&ctx, block0);
    memcpy(otk, block0, 32u);
    scrypt_chacha20_wipe(&ctx);
    scrypt_zeroize(block0, sizeof(block0));
}

static void compute_tag(const uint8_t otk[32],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        uint8_t tag[16]) {
    scrypt_poly1305_ctx pctx;
    scrypt_poly1305_init(&pctx, otk);

    if (aad_len > 0u) {
        scrypt_poly1305_update(&pctx, aad, aad_len);
        scrypt_poly1305_pad16(&pctx);
    }
    if (ct_len > 0u) {
        scrypt_poly1305_update(&pctx, ct, ct_len);
        scrypt_poly1305_pad16(&pctx);
    }

    uint8_t lens[16];
    scrypt_store64_le(lens + 0u, (uint64_t)aad_len);
    scrypt_store64_le(lens + 8u, (uint64_t)ct_len);
    scrypt_poly1305_update(&pctx, lens, sizeof(lens));
    scrypt_poly1305_final(&pctx, tag);
    scrypt_zeroize(lens, sizeof(lens));
}

void scrypt_xchacha20_poly1305_encrypt(
    const uint8_t key[SCRYPT_XCHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce24[SCRYPT_XCHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext,
    uint8_t tag[SCRYPT_XCHACHA20_POLY1305_TAG_SIZE]) {
    uint8_t subkey[32];
    uint8_t nonce12[12];
    uint8_t otk[32];

    scrypt_hchacha20(key, nonce24, subkey);
    build_subnonce12(nonce24, nonce12);
    derive_otk(subkey, nonce12, otk);

    scrypt_chacha20_ctx cctx;
    scrypt_chacha20_init(&cctx, subkey, 1u, nonce12);
    scrypt_chacha20_xor(&cctx, plaintext, ciphertext, pt_len);
    scrypt_chacha20_wipe(&cctx);

    compute_tag(otk, aad, aad_len, ciphertext, pt_len, tag);

    scrypt_zeroize(subkey, sizeof(subkey));
    scrypt_zeroize(nonce12, sizeof(nonce12));
    scrypt_zeroize(otk, sizeof(otk));
}

int scrypt_xchacha20_poly1305_decrypt(
    const uint8_t key[SCRYPT_XCHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce24[SCRYPT_XCHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[SCRYPT_XCHACHA20_POLY1305_TAG_SIZE],
    uint8_t *plaintext) {
    uint8_t subkey[32];
    uint8_t nonce12[12];
    uint8_t otk[32];
    uint8_t expected[16];

    scrypt_hchacha20(key, nonce24, subkey);
    build_subnonce12(nonce24, nonce12);
    derive_otk(subkey, nonce12, otk);

    compute_tag(otk, aad, aad_len, ciphertext, ct_len, expected);
    scrypt_zeroize(otk, sizeof(otk));

    if (ct_verify16(expected, tag) != 0) {
        scrypt_zeroize(expected, sizeof(expected));
        scrypt_zeroize(subkey, sizeof(subkey));
        scrypt_zeroize(nonce12, sizeof(nonce12));
        if (plaintext != NULL && ct_len > 0u) scrypt_zeroize(plaintext, ct_len);
        return SCRYPT_XCHACHA20_AEAD_ERR_AUTH;
    }
    scrypt_zeroize(expected, sizeof(expected));

    scrypt_chacha20_ctx cctx;
    scrypt_chacha20_init(&cctx, subkey, 1u, nonce12);
    scrypt_chacha20_xor(&cctx, ciphertext, plaintext, ct_len);
    scrypt_chacha20_wipe(&cctx);

    scrypt_zeroize(subkey, sizeof(subkey));
    scrypt_zeroize(nonce12, sizeof(nonce12));
    return SCRYPT_XCHACHA20_AEAD_OK;
}
