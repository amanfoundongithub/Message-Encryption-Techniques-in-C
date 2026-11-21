#include "scrypt/kdf/hkdf_sha256.h"
#include "internal/zeroize.h"
#include <string.h>

void scrypt_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t prk[SCRYPT_HKDF_SHA256_HASH_LEN]) {
    uint8_t zero_salt[SCRYPT_HKDF_SHA256_HASH_LEN];
    if (salt == NULL || salt_len == 0u) {
        memset(zero_salt, 0, sizeof(zero_salt));
        scrypt_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, ikm_len, prk);
        scrypt_zeroize(zero_salt, sizeof(zero_salt));
    } else {
        scrypt_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

int scrypt_hkdf_sha256_expand(const uint8_t prk[SCRYPT_HKDF_SHA256_HASH_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t *okm, size_t okm_len) {
    if (okm == NULL && okm_len > 0u) {
        return SCRYPT_HKDF_ERR_PARAM;
    }
    if (okm_len > SCRYPT_HKDF_SHA256_MAX_OKM) {
        return SCRYPT_HKDF_ERR_PARAM;
    }
    if (okm_len == 0u) {
        return SCRYPT_HKDF_OK;
    }

    unsigned n_blocks = (unsigned)((okm_len + SCRYPT_HKDF_SHA256_HASH_LEN - 1u) / SCRYPT_HKDF_SHA256_HASH_LEN);
    uint8_t prev[SCRYPT_HKDF_SHA256_HASH_LEN];
    uint8_t block[SCRYPT_HKDF_SHA256_HASH_LEN];
    size_t out_pos = 0u;

    for (unsigned counter = 1u; counter <= n_blocks; counter++) {
        scrypt_hmac_sha256_ctx hctx;
        scrypt_hmac_sha256_init(&hctx, prk, SCRYPT_HKDF_SHA256_HASH_LEN);

        if (counter > 1u) {
            scrypt_hmac_sha256_update(&hctx, prev, sizeof(prev));
        }
        if (info != NULL && info_len > 0u) {
            scrypt_hmac_sha256_update(&hctx, info, info_len);
        }
        uint8_t c_byte = (uint8_t)counter;
        scrypt_hmac_sha256_update(&hctx, &c_byte, 1u);
        scrypt_hmac_sha256_final(&hctx, block);

        memcpy(prev, block, sizeof(prev));

        size_t take = okm_len - out_pos;
        if (take > SCRYPT_HKDF_SHA256_HASH_LEN) {
            take = SCRYPT_HKDF_SHA256_HASH_LEN;
        }
        memcpy(okm + out_pos, block, take);
        out_pos += take;
    }

    scrypt_zeroize(prev, sizeof(prev));
    scrypt_zeroize(block, sizeof(block));
    return SCRYPT_HKDF_OK;
}

int scrypt_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len) {
    uint8_t prk[SCRYPT_HKDF_SHA256_HASH_LEN];
    scrypt_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    int rc = scrypt_hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
    scrypt_zeroize(prk, sizeof(prk));
    return rc;
}
