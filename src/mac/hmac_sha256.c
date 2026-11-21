#include "scrypt/mac/hmac_sha256.h"
#include "internal/zeroize.h"
#include <string.h>

void scrypt_hmac_sha256_init(scrypt_hmac_sha256_ctx *ctx,
                               const uint8_t *key,
                               size_t key_len) {
    uint8_t k_block[SCRYPT_HMAC_SHA256_BLOCK_SIZE];
    uint8_t pad[SCRYPT_HMAC_SHA256_BLOCK_SIZE];

    memset(k_block, 0, sizeof(k_block));

    /* RFC 2104 Section 2: keys longer than block size are hashed first */
    if (key_len > SCRYPT_HMAC_SHA256_BLOCK_SIZE) {
        scrypt_sha256(key, key_len, k_block);
    } else if (key_len > 0u && key != NULL) {
        memcpy(k_block, key, key_len);
    }

    /* Inner hash: SHA-256((K0 ^ ipad) || message) */
    for (size_t i = 0u; i < SCRYPT_HMAC_SHA256_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_block[i] ^ 0x36u);
    }
    scrypt_sha256_init(&ctx->inner);
    scrypt_sha256_update(&ctx->inner, pad, sizeof(pad));

    /* Outer hash: SHA-256((K0 ^ opad) || inner_digest) */
    for (size_t i = 0u; i < SCRYPT_HMAC_SHA256_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_block[i] ^ 0x5cu);
    }
    scrypt_sha256_init(&ctx->outer);
    scrypt_sha256_update(&ctx->outer, pad, sizeof(pad));

    scrypt_zeroize(k_block, sizeof(k_block));
    scrypt_zeroize(pad, sizeof(pad));
}

void scrypt_hmac_sha256_update(scrypt_hmac_sha256_ctx *ctx,
                                 const void *data,
                                 size_t len) {
    scrypt_sha256_update(&ctx->inner, data, len);
}

void scrypt_hmac_sha256_final(scrypt_hmac_sha256_ctx *ctx,
                                uint8_t mac[SCRYPT_HMAC_SHA256_DIGEST_SIZE]) {
    uint8_t inner_digest[SCRYPT_HMAC_SHA256_DIGEST_SIZE];
    scrypt_sha256_final(&ctx->inner, inner_digest);

    scrypt_sha256_update(&ctx->outer, inner_digest, sizeof(inner_digest));
    scrypt_sha256_final(&ctx->outer, mac);

    scrypt_zeroize(inner_digest, sizeof(inner_digest));
    scrypt_zeroize(ctx, sizeof(*ctx));
}

void scrypt_hmac_sha256(const uint8_t *key,
                          size_t key_len,
                          const void *data,
                          size_t len,
                          uint8_t mac[SCRYPT_HMAC_SHA256_DIGEST_SIZE]) {
    scrypt_hmac_sha256_ctx ctx;
    scrypt_hmac_sha256_init(&ctx, key, key_len);
    scrypt_hmac_sha256_update(&ctx, data, len);
    scrypt_hmac_sha256_final(&ctx, mac);
}

void scrypt_hmac_sha256_wipe(scrypt_hmac_sha256_ctx *ctx) {
    scrypt_zeroize(ctx, sizeof(*ctx));
}
