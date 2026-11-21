#include "scrypt/hash/sha256.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (rotr32((x), 2)  ^ rotr32((x), 13) ^ rotr32((x), 22))
#define EP1(x)       (rotr32((x), 6)  ^ rotr32((x), 11) ^ rotr32((x), 25))
#define SIG0(x)      (rotr32((x), 7)  ^ rotr32((x), 18) ^ ((x) >> 3))
#define SIG1(x)      (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16u; i++) {
        w[i] = scrypt_load32_be(block + i * 4u);
    }
    for (unsigned i = 16u; i < 64u; i++) {
        w[i] = SIG1(w[i - 2u]) + w[i - 7u] + SIG0(w[i - 15u]) + w[i - 16u];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (unsigned i = 0; i < 64u; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K256[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    scrypt_zeroize(w, sizeof(w));
}

void scrypt_sha256_init(scrypt_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void scrypt_sha256_update(scrypt_sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buf_idx = (size_t)(ctx->count % SCRYPT_SHA256_BLOCK_SIZE);
    ctx->count += (uint64_t)len;

    if (buf_idx > 0) {
        size_t needed = SCRYPT_SHA256_BLOCK_SIZE - buf_idx;
        if (len < needed) {
            memcpy(ctx->buffer + buf_idx, p, len);
            return;
        }
        memcpy(ctx->buffer + buf_idx, p, needed);
        sha256_transform(ctx->state, ctx->buffer);
        p += needed;
        len -= needed;
    }

    while (len >= SCRYPT_SHA256_BLOCK_SIZE) {
        sha256_transform(ctx->state, p);
        p += SCRYPT_SHA256_BLOCK_SIZE;
        len -= SCRYPT_SHA256_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

void scrypt_sha256_final(scrypt_sha256_ctx *ctx, uint8_t digest[SCRYPT_SHA256_DIGEST_SIZE]) {
    size_t buf_idx = (size_t)(ctx->count % SCRYPT_SHA256_BLOCK_SIZE);
    ctx->buffer[buf_idx++] = 0x80u;

    if (buf_idx > 56u) {
        memset(ctx->buffer + buf_idx, 0, SCRYPT_SHA256_BLOCK_SIZE - buf_idx);
        sha256_transform(ctx->state, ctx->buffer);
        memset(ctx->buffer, 0, 56u);
    } else {
        memset(ctx->buffer + buf_idx, 0, 56u - buf_idx);
    }

    uint64_t total_bits = ctx->count * 8u;
    scrypt_store64_be(ctx->buffer + 56u, total_bits);
    sha256_transform(ctx->state, ctx->buffer);

    for (unsigned i = 0; i < 8u; i++) {
        scrypt_store32_be(digest + i * 4u, ctx->state[i]);
    }

    scrypt_zeroize(ctx, sizeof(*ctx));
}

void scrypt_sha256(const void *data, size_t len, uint8_t digest[SCRYPT_SHA256_DIGEST_SIZE]) {
    scrypt_sha256_ctx ctx;
    scrypt_sha256_init(&ctx);
    scrypt_sha256_update(&ctx, data, len);
    scrypt_sha256_final(&ctx, digest);
}

void scrypt_sha256_wipe(scrypt_sha256_ctx *ctx) {
    scrypt_zeroize(ctx, sizeof(*ctx));
}
