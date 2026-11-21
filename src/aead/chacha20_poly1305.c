#include "scrypt/aead/chacha20_poly1305.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static int ct_verify16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0u;
    for (size_t i = 0u; i < 16u; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0u) ? 0 : -1;
}

static void derive_poly1305_key(const uint8_t key[32],
                                const uint8_t nonce[12],
                                uint8_t otk[32]) {
    uint8_t block0[64];
    scrypt_chacha20_ctx ctx;
    scrypt_chacha20_init(&ctx, key, 0u, nonce);
    scrypt_chacha20_block(&ctx, block0);
    memcpy(otk, block0, 32u);
    scrypt_chacha20_wipe(&ctx);
    scrypt_zeroize(block0, sizeof(block0));
}

static void compute_aead_tag(const uint8_t otk[32],
                             const uint8_t *aad,
                             size_t aad_len,
                             const uint8_t *ciphertext,
                             size_t ct_len,
                             uint8_t tag[16]) {
    scrypt_poly1305_ctx pctx;
    scrypt_poly1305_init(&pctx, otk);

    if (aad_len > 0u) {
        scrypt_poly1305_update(&pctx, aad, aad_len);
        scrypt_poly1305_pad16(&pctx);
    }

    if (ct_len > 0u) {
        scrypt_poly1305_update(&pctx, ciphertext, ct_len);
        scrypt_poly1305_pad16(&pctx);
    }

    uint8_t lengths[16];
    scrypt_store64_le(lengths + 0u, (uint64_t)aad_len);
    scrypt_store64_le(lengths + 8u, (uint64_t)ct_len);
    scrypt_poly1305_update(&pctx, lengths, sizeof(lengths));

    scrypt_poly1305_final(&pctx, tag);
    scrypt_zeroize(lengths, sizeof(lengths));
}

void scrypt_chacha20_poly1305_encrypt(
    const uint8_t key[SCRYPT_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[SCRYPT_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *ciphertext,
    uint8_t tag[SCRYPT_CHACHA20_POLY1305_TAG_SIZE]) {
    uint8_t otk[32];
    derive_poly1305_key(key, nonce, otk);

    scrypt_chacha20_ctx cctx;
    scrypt_chacha20_init(&cctx, key, 1u, nonce);
    scrypt_chacha20_xor(&cctx, plaintext, ciphertext, pt_len);
    scrypt_chacha20_wipe(&cctx);

    compute_aead_tag(otk, aad, aad_len, ciphertext, pt_len, tag);
    scrypt_zeroize(otk, sizeof(otk));
}

int scrypt_chacha20_poly1305_decrypt(
    const uint8_t key[SCRYPT_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[SCRYPT_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ct_len,
    const uint8_t tag[SCRYPT_CHACHA20_POLY1305_TAG_SIZE],
    uint8_t *plaintext) {
    uint8_t otk[32];
    derive_poly1305_key(key, nonce, otk);

    uint8_t expected_tag[16];
    compute_aead_tag(otk, aad, aad_len, ciphertext, ct_len, expected_tag);
    scrypt_zeroize(otk, sizeof(otk));

    if (ct_verify16(expected_tag, tag) != 0) {
        scrypt_zeroize(expected_tag, sizeof(expected_tag));
        if (plaintext != NULL && ct_len > 0u) {
            scrypt_zeroize(plaintext, ct_len);
        }
        return SCRYPT_AEAD_ERR_AUTH;
    }

    scrypt_zeroize(expected_tag, sizeof(expected_tag));

    scrypt_chacha20_ctx cctx;
    scrypt_chacha20_init(&cctx, key, 1u, nonce);
    scrypt_chacha20_xor(&cctx, ciphertext, plaintext, ct_len);
    scrypt_chacha20_wipe(&cctx);

    return SCRYPT_AEAD_OK;
}
