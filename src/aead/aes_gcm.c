#include "scrypt/aead/aes_gcm.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

typedef void (*aes_enc_fn)(const void *ctx, const uint8_t in[16], uint8_t out[16]);

/* GHASH multiplication in GF(2^128) with NIST SP 800-38D bit-reflected ordering (R = 0xe1 << 120) */
static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    memcpy(v, h, 16u);

    for (unsigned i = 0u; i < 128u; i++) {
        unsigned byte_idx = i / 8u;
        unsigned bit_mask = 1u << (7u - (i % 8u));

        if (x[byte_idx] & bit_mask) {
            for (unsigned k = 0u; k < 16u; k++) z[k] ^= v[k];
        }

        uint8_t lsb = v[15] & 1u;
        for (int k = 15; k > 0; k--) {
            v[k] = (uint8_t)((v[k] >> 1) | ((v[k - 1] & 1u) << 7));
        }
        v[0] = (uint8_t)(v[0] >> 1);
        if (lsb) {
            v[0] ^= 0xe1u;
        }
    }

    memcpy(x, z, 16u);
    scrypt_zeroize(v, sizeof(v));
    scrypt_zeroize(z, sizeof(z));
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
    size_t off = 0u;
    while (off < len) {
        uint8_t blk[16] = {0};
        size_t take = len - off;
        if (take > 16u) take = 16u;
        memcpy(blk, data + off, take);
        for (size_t i = 0u; i < 16u; i++) y[i] ^= blk[i];
        ghash_mul(y, h);
        off += take;
    }
}

static void inc32_be(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) break;
    }
}

static void compute_j0(aes_enc_fn enc, const void *cipher_ctx,
                       const uint8_t h[16],
                       const uint8_t *iv, size_t iv_len,
                       uint8_t j0[16]) {
    memset(j0, 0, 16u);
    if (iv_len == 12u) {
        memcpy(j0, iv, 12u);
        j0[15] = 0x01u;
    } else {
        ghash_update(j0, h, iv, iv_len);
        uint8_t len_blk[16] = {0};
        scrypt_store64_be(len_blk + 8u, (uint64_t)iv_len * 8u);
        ghash_update(j0, h, len_blk, 16u);
        scrypt_zeroize(len_blk, sizeof(len_blk));
    }
    (void)enc;
    (void)cipher_ctx;
}

static void gctr(aes_enc_fn enc, const void *cipher_ctx,
                 const uint8_t icb[16],
                 const uint8_t *in, size_t len,
                 uint8_t *out) {
    if (len == 0u) return;
    uint8_t cb[16];
    uint8_t ks[16];
    memcpy(cb, icb, 16u);

    size_t off = 0u;
    while (off < len) {
        enc(cipher_ctx, cb, ks);
        size_t take = len - off;
        if (take > 16u) take = 16u;
        for (size_t i = 0u; i < take; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
        inc32_be(cb);
        off += take;
    }

    scrypt_zeroize(cb, sizeof(cb));
    scrypt_zeroize(ks, sizeof(ks));
}

static int ct_verify16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0u;
    for (size_t i = 0u; i < 16u; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return (diff == 0u) ? 0 : -1;
}

static int gcm_encrypt_core(aes_enc_fn enc, const void *cipher_ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[16]) {
    if (iv == NULL || iv_len == 0u) return SCRYPT_GCM_ERR_PARAM;
    if ((pt_len > 0u && (pt == NULL || ct == NULL)) || (aad_len > 0u && aad == NULL)) {
        return SCRYPT_GCM_ERR_PARAM;
    }

    uint8_t zero16[16] = {0};
    uint8_t h[16];
    enc(cipher_ctx, zero16, h);

    uint8_t j0[16];
    compute_j0(enc, cipher_ctx, h, iv, iv_len, j0);

    uint8_t j0_inc[16];
    memcpy(j0_inc, j0, 16u);
    inc32_be(j0_inc);
    gctr(enc, cipher_ctx, j0_inc, pt, pt_len, ct);

    uint8_t s[16] = {0};
    ghash_update(s, h, aad, aad_len);
    ghash_update(s, h, ct, pt_len);

    uint8_t lens[16];
    scrypt_store64_be(lens + 0u, (uint64_t)aad_len * 8u);
    scrypt_store64_be(lens + 8u, (uint64_t)pt_len * 8u);
    ghash_update(s, h, lens, 16u);

    uint8_t enc_j0[16];
    enc(cipher_ctx, j0, enc_j0);
    for (size_t i = 0u; i < 16u; i++) tag[i] = (uint8_t)(s[i] ^ enc_j0[i]);

    scrypt_zeroize(h, sizeof(h));
    scrypt_zeroize(j0, sizeof(j0));
    scrypt_zeroize(j0_inc, sizeof(j0_inc));
    scrypt_zeroize(s, sizeof(s));
    scrypt_zeroize(lens, sizeof(lens));
    scrypt_zeroize(enc_j0, sizeof(enc_j0));
    return SCRYPT_GCM_OK;
}

static int gcm_decrypt_core(aes_enc_fn enc, const void *cipher_ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[16], uint8_t *pt) {
    if (iv == NULL || iv_len == 0u || tag == NULL) return SCRYPT_GCM_ERR_PARAM;
    if ((ct_len > 0u && (ct == NULL || pt == NULL)) || (aad_len > 0u && aad == NULL)) {
        return SCRYPT_GCM_ERR_PARAM;
    }

    uint8_t zero16[16] = {0};
    uint8_t h[16];
    enc(cipher_ctx, zero16, h);

    uint8_t j0[16];
    compute_j0(enc, cipher_ctx, h, iv, iv_len, j0);

    uint8_t s[16] = {0};
    ghash_update(s, h, aad, aad_len);
    ghash_update(s, h, ct, ct_len);

    uint8_t lens[16];
    scrypt_store64_be(lens + 0u, (uint64_t)aad_len * 8u);
    scrypt_store64_be(lens + 8u, (uint64_t)ct_len * 8u);
    ghash_update(s, h, lens, 16u);

    uint8_t enc_j0[16];
    enc(cipher_ctx, j0, enc_j0);
    uint8_t expected[16];
    for (size_t i = 0u; i < 16u; i++) expected[i] = (uint8_t)(s[i] ^ enc_j0[i]);

    scrypt_zeroize(h, sizeof(h));
    scrypt_zeroize(s, sizeof(s));
    scrypt_zeroize(lens, sizeof(lens));
    scrypt_zeroize(enc_j0, sizeof(enc_j0));

    if (ct_verify16(expected, tag) != 0) {
        scrypt_zeroize(expected, sizeof(expected));
        scrypt_zeroize(j0, sizeof(j0));
        if (pt != NULL && ct_len > 0u) scrypt_zeroize(pt, ct_len);
        return SCRYPT_GCM_ERR_AUTH;
    }

    scrypt_zeroize(expected, sizeof(expected));
    uint8_t j0_inc[16];
    memcpy(j0_inc, j0, 16u);
    inc32_be(j0_inc);
    gctr(enc, cipher_ctx, j0_inc, ct, ct_len, pt);

    scrypt_zeroize(j0, sizeof(j0));
    scrypt_zeroize(j0_inc, sizeof(j0_inc));
    return SCRYPT_GCM_OK;
}

static void aes128_enc_wrapper(const void *ctx, const uint8_t in[16], uint8_t out[16]) {
    scrypt_aes128_encrypt_block((const scrypt_aes128_ctx *)ctx, in, out);
}

static void aes256_enc_wrapper(const void *ctx, const uint8_t in[16], uint8_t out[16]) {
    scrypt_aes256_encrypt_block((const scrypt_aes256_ctx *)ctx, in, out);
}

int scrypt_aes128_gcm_encrypt(const uint8_t key[16],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext,
                              uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE]) {
    scrypt_aes128_ctx ctx;
    scrypt_aes128_init(&ctx, key);
    int rc = gcm_encrypt_core(aes128_enc_wrapper, &ctx, iv, iv_len, aad, aad_len, plaintext, pt_len, ciphertext, tag);
    scrypt_aes128_wipe(&ctx);
    return rc;
}

int scrypt_aes128_gcm_decrypt(const uint8_t key[16],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              const uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE],
                              uint8_t *plaintext) {
    scrypt_aes128_ctx ctx;
    scrypt_aes128_init(&ctx, key);
    int rc = gcm_decrypt_core(aes128_enc_wrapper, &ctx, iv, iv_len, aad, aad_len, ciphertext, ct_len, tag, plaintext);
    scrypt_aes128_wipe(&ctx);
    return rc;
}

int scrypt_aes256_gcm_encrypt(const uint8_t key[32],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext,
                              uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE]) {
    scrypt_aes256_ctx ctx;
    scrypt_aes256_init(&ctx, key);
    int rc = gcm_encrypt_core(aes256_enc_wrapper, &ctx, iv, iv_len, aad, aad_len, plaintext, pt_len, ciphertext, tag);
    scrypt_aes256_wipe(&ctx);
    return rc;
}

int scrypt_aes256_gcm_decrypt(const uint8_t key[32],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              const uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE],
                              uint8_t *plaintext) {
    scrypt_aes256_ctx ctx;
    scrypt_aes256_init(&ctx, key);
    int rc = gcm_decrypt_core(aes256_enc_wrapper, &ctx, iv, iv_len, aad, aad_len, ciphertext, ct_len, tag, plaintext);
    scrypt_aes256_wipe(&ctx);
    return rc;
}
