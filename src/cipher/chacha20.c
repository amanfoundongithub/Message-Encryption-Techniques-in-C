#include "scrypt/cipher/chacha20.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

#define QUARTERROUND(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16u); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12u); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8u);  \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7u);  \
} while (0)

void scrypt_chacha20_init(scrypt_chacha20_ctx *ctx,
                           const uint8_t key[SCRYPT_CHACHA20_KEY_SIZE],
                           uint32_t counter,
                           const uint8_t nonce[SCRYPT_CHACHA20_NONCE_SIZE]) {
    /* "expand 32-byte k" in little-endian 32-bit words (RFC 8439 Section 2.3) */
    ctx->state[0] = 0x61707865u;
    ctx->state[1] = 0x3320646eu;
    ctx->state[2] = 0x79622d32u;
    ctx->state[3] = 0x6b206574u;

    for (unsigned i = 0u; i < 8u; i++) {
        ctx->state[4u + i] = scrypt_load32_le(key + i * 4u);
    }

    ctx->state[12] = counter;
    ctx->state[13] = scrypt_load32_le(nonce + 0u);
    ctx->state[14] = scrypt_load32_le(nonce + 4u);
    ctx->state[15] = scrypt_load32_le(nonce + 8u);
}

void scrypt_chacha20_set_counter(scrypt_chacha20_ctx *ctx, uint32_t counter) {
    ctx->state[12] = counter;
}

void scrypt_chacha20_block(const scrypt_chacha20_ctx *ctx,
                           uint8_t out[SCRYPT_CHACHA20_BLOCK_SIZE]) {
    uint32_t x[16];
    memcpy(x, ctx->state, sizeof(x));

    /* 20 rounds = 10 column + diagonal double-rounds */
    for (unsigned i = 0u; i < 10u; i++) {
        /* Column rounds */
        QUARTERROUND(x[0], x[4],  x[8], x[12]);
        QUARTERROUND(x[1], x[5],  x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);

        /* Diagonal rounds */
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7],  x[8], x[13]);
        QUARTERROUND(x[3], x[4],  x[9], x[14]);
    }

    for (unsigned i = 0u; i < 16u; i++) {
        uint32_t sum = x[i] + ctx->state[i];
        scrypt_store32_le(out + i * 4u, sum);
    }

    scrypt_zeroize(x, sizeof(x));
}

void scrypt_chacha20_xor(scrypt_chacha20_ctx *ctx,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len) {
    uint8_t keystream[SCRYPT_CHACHA20_BLOCK_SIZE];
    size_t offset = 0u;

    while (offset < len) {
        scrypt_chacha20_block(ctx, keystream);
        ctx->state[12] += 1u;

        size_t chunk = len - offset;
        if (chunk > SCRYPT_CHACHA20_BLOCK_SIZE) {
            chunk = SCRYPT_CHACHA20_BLOCK_SIZE;
        }

        for (size_t i = 0u; i < chunk; i++) {
            out[offset + i] = (uint8_t)(in[offset + i] ^ keystream[i]);
        }
        offset += chunk;
    }

    scrypt_zeroize(keystream, sizeof(keystream));
}

void scrypt_chacha20_wipe(scrypt_chacha20_ctx *ctx) {
    scrypt_zeroize(ctx, sizeof(*ctx));
}
