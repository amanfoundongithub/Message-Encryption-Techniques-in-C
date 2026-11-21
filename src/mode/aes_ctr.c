#include "scrypt/mode/aes_ctr.h"
#include "internal/zeroize.h"
#include <string.h>

static void inc128_be(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; i--) {
        ctr[i] = (uint8_t)(ctr[i] + 1u);
        if (ctr[i] != 0u) {
            break;
        }
    }
}

void scrypt_aes128_ctr_init(scrypt_aes128_ctr_ctx *ctx,
                            const uint8_t key[SCRYPT_AES128_KEY_SIZE],
                            const uint8_t iv[SCRYPT_AES_CTR_IV_SIZE]) {
    scrypt_aes128_init(&ctx->cipher, key);
    memcpy(ctx->counter, iv, SCRYPT_AES_CTR_IV_SIZE);
    memset(ctx->keystream, 0, sizeof(ctx->keystream));
    ctx->ks_offset = SCRYPT_AES_CTR_BLOCK_SIZE;
}

void scrypt_aes128_ctr_xor(scrypt_aes128_ctr_ctx *ctx,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t len) {
    size_t i = 0u;
    while (i < len) {
        if (ctx->ks_offset == SCRYPT_AES_CTR_BLOCK_SIZE) {
            scrypt_aes128_encrypt_block(&ctx->cipher, ctx->counter, ctx->keystream);
            inc128_be(ctx->counter);
            ctx->ks_offset = 0u;
        }
        out[i] = (uint8_t)(in[i] ^ ctx->keystream[ctx->ks_offset]);
        ctx->ks_offset++;
        i++;
    }
}

void scrypt_aes128_ctr_wipe(scrypt_aes128_ctr_ctx *ctx) {
    scrypt_aes128_wipe(&ctx->cipher);
    scrypt_zeroize(ctx->counter, sizeof(ctx->counter));
    scrypt_zeroize(ctx->keystream, sizeof(ctx->keystream));
    ctx->ks_offset = 0u;
}

void scrypt_aes256_ctr_init(scrypt_aes256_ctr_ctx *ctx,
                            const uint8_t key[SCRYPT_AES256_KEY_SIZE],
                            const uint8_t iv[SCRYPT_AES_CTR_IV_SIZE]) {
    scrypt_aes256_init(&ctx->cipher, key);
    memcpy(ctx->counter, iv, SCRYPT_AES_CTR_IV_SIZE);
    memset(ctx->keystream, 0, sizeof(ctx->keystream));
    ctx->ks_offset = SCRYPT_AES_CTR_BLOCK_SIZE;
}

void scrypt_aes256_ctr_xor(scrypt_aes256_ctr_ctx *ctx,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t len) {
    size_t i = 0u;
    while (i < len) {
        if (ctx->ks_offset == SCRYPT_AES_CTR_BLOCK_SIZE) {
            scrypt_aes256_encrypt_block(&ctx->cipher, ctx->counter, ctx->keystream);
            inc128_be(ctx->counter);
            ctx->ks_offset = 0u;
        }
        out[i] = (uint8_t)(in[i] ^ ctx->keystream[ctx->ks_offset]);
        ctx->ks_offset++;
        i++;
    }
}

void scrypt_aes256_ctr_wipe(scrypt_aes256_ctr_ctx *ctx) {
    scrypt_aes256_wipe(&ctx->cipher);
    scrypt_zeroize(ctx->counter, sizeof(ctx->counter));
    scrypt_zeroize(ctx->keystream, sizeof(ctx->keystream));
    ctx->ks_offset = 0u;
}
