#include "scrypt/mac/poly1305.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static void poly1305_process_blocks(scrypt_poly1305_ctx *ctx,
                                    const uint8_t *m,
                                    size_t bytes,
                                    uint32_t hibit) {
    const uint32_t r0 = ctx->r[0];
    const uint32_t r1 = ctx->r[1];
    const uint32_t r2 = ctx->r[2];
    const uint32_t r3 = ctx->r[3];
    const uint32_t r4 = ctx->r[4];

    const uint32_t s1 = r1 * 5u;
    const uint32_t s2 = r2 * 5u;
    const uint32_t s3 = r3 * 5u;
    const uint32_t s4 = r4 * 5u;

    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    while (bytes >= 16u) {
        h0 += (scrypt_load32_le(m + 0u))       & 0x3ffffffu;
        h1 += (scrypt_load32_le(m + 3u) >> 2)  & 0x3ffffffu;
        h2 += (scrypt_load32_le(m + 6u) >> 4)  & 0x3ffffffu;
        h3 += (scrypt_load32_le(m + 9u) >> 6)  & 0x3ffffffu;
        h4 += (scrypt_load32_le(m + 12u) >> 8) | (hibit << 24);

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
                      (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
                      (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
                      (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
                      (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
                      (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint64_t c;
        c = d0 >> 26; h0 = (uint32_t)d0 & 0x3ffffffu;
        d1 += c; c = d1 >> 26; h1 = (uint32_t)d1 & 0x3ffffffu;
        d2 += c; c = d2 >> 26; h2 = (uint32_t)d2 & 0x3ffffffu;
        d3 += c; c = d3 >> 26; h3 = (uint32_t)d3 & 0x3ffffffu;
        d4 += c; c = d4 >> 26; h4 = (uint32_t)d4 & 0x3ffffffu;

        h0 += (uint32_t)c * 5u;
        c = h0 >> 26; h0 &= 0x3ffffffu;
        h1 += (uint32_t)c;

        m += 16u;
        bytes -= 16u;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void scrypt_poly1305_init(scrypt_poly1305_ctx *ctx,
                            const uint8_t key[SCRYPT_POLY1305_KEY_SIZE]) {
    memset(ctx, 0, sizeof(*ctx));

    /* Clamp r per RFC 8439 Section 2.5 */
    uint8_t rc[16];
    memcpy(rc, key, 16u);
    rc[3]  &= 15u;
    rc[7]  &= 15u;
    rc[11] &= 15u;
    rc[15] &= 15u;
    rc[4]  &= 252u;
    rc[8]  &= 252u;
    rc[12] &= 252u;

    ctx->r[0] = (scrypt_load32_le(rc + 0u))        & 0x3ffffffu;
    ctx->r[1] = (scrypt_load32_le(rc + 3u) >> 2)   & 0x3ffffffu;
    ctx->r[2] = (scrypt_load32_le(rc + 6u) >> 4)   & 0x3ffffffu;
    ctx->r[3] = (scrypt_load32_le(rc + 9u) >> 6)   & 0x3ffffffu;
    ctx->r[4] = (scrypt_load32_le(rc + 12u) >> 8)  & 0x0ffffffu;

    ctx->pad[0] = scrypt_load32_le(key + 16u);
    ctx->pad[1] = scrypt_load32_le(key + 20u);
    ctx->pad[2] = scrypt_load32_le(key + 24u);
    ctx->pad[3] = scrypt_load32_le(key + 28u);

    scrypt_zeroize(rc, sizeof(rc));
}

void scrypt_poly1305_update(scrypt_poly1305_ctx *ctx,
                              const uint8_t *msg,
                              size_t len) {
    if (ctx->buf_len > 0u) {
        size_t take = 16u - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buf + ctx->buf_len, msg, take);
        ctx->buf_len += take;
        msg += take;
        len -= take;

        if (ctx->buf_len == 16u) {
            poly1305_process_blocks(ctx, ctx->buf, 16u, 1u);
            ctx->buf_len = 0u;
        }
    }

    if (len >= 16u) {
        size_t full_blocks = len & ~(size_t)15u;
        poly1305_process_blocks(ctx, msg, full_blocks, 1u);
        msg += full_blocks;
        len -= full_blocks;
    }

    if (len > 0u) {
        memcpy(ctx->buf, msg, len);
        ctx->buf_len = len;
    }
}

void scrypt_poly1305_pad16(scrypt_poly1305_ctx *ctx) {
    if (ctx->buf_len > 0u) {
        memset(ctx->buf + ctx->buf_len, 0, 16u - ctx->buf_len);
        poly1305_process_blocks(ctx, ctx->buf, 16u, 1u);
        ctx->buf_len = 0u;
    }
}

void scrypt_poly1305_final(scrypt_poly1305_ctx *ctx,
                             uint8_t tag[SCRYPT_POLY1305_TAG_SIZE]) {
    if (ctx->buf_len > 0u) {
        uint8_t last[16] = {0};
        memcpy(last, ctx->buf, ctx->buf_len);
        last[ctx->buf_len] = 0x01u;

        ctx->h[0] += (scrypt_load32_le(last + 0u))       & 0x3ffffffu;
        ctx->h[1] += (scrypt_load32_le(last + 3u) >> 2)  & 0x3ffffffu;
        ctx->h[2] += (scrypt_load32_le(last + 6u) >> 4)  & 0x3ffffffu;
        ctx->h[3] += (scrypt_load32_le(last + 9u) >> 6)  & 0x3ffffffu;
        ctx->h[4] += (scrypt_load32_le(last + 12u) >> 8);

        const uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
        const uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
        uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint64_t c;
        c = d0 >> 26; h0 = (uint32_t)d0 & 0x3ffffffu;
        d1 += c; c = d1 >> 26; h1 = (uint32_t)d1 & 0x3ffffffu;
        d2 += c; c = d2 >> 26; h2 = (uint32_t)d2 & 0x3ffffffu;
        d3 += c; c = d3 >> 26; h3 = (uint32_t)d3 & 0x3ffffffu;
        d4 += c; c = d4 >> 26; h4 = (uint32_t)d4 & 0x3ffffffu;
        h0 += (uint32_t)c * 5u;
        c = h0 >> 26; h0 &= 0x3ffffffu;
        h1 += (uint32_t)c;

        ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
        ctx->buf_len = 0u;
        scrypt_zeroize(last, sizeof(last));
    }

    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;

    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    /* Compute g = h + 5 - 2^130 to test if h >= 2^130 - 5 */
    uint32_t g0 = h0 + 5u;
    c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + c;
    c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + c;
    c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + c;
    c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    /* Select g if (g4 >> 31) == 0 (i.e. no underflow), else keep h */
    uint32_t mask = (g4 >> 31) - 1u;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* Convert 5x26-bit h to four 32-bit words and add pad (mod 2^128) */
    uint64_t f0 = (uint64_t)(h0 | (h1 << 26)) + (uint64_t)ctx->pad[0];
    uint32_t w0 = (uint32_t)f0;

    uint64_t f1 = (uint64_t)((h1 >> 6) | (h2 << 20)) + (uint64_t)ctx->pad[1] + (f0 >> 32);
    uint32_t w1 = (uint32_t)f1;

    uint64_t f2 = (uint64_t)((h2 >> 12) | (h3 << 14)) + (uint64_t)ctx->pad[2] + (f1 >> 32);
    uint32_t w2 = (uint32_t)f2;

    uint64_t f3 = (uint64_t)((h3 >> 18) | (h4 << 8))  + (uint64_t)ctx->pad[3] + (f2 >> 32);
    uint32_t w3 = (uint32_t)f3;

    scrypt_store32_le(tag + 0u,  w0);
    scrypt_store32_le(tag + 4u,  w1);
    scrypt_store32_le(tag + 8u,  w2);
    scrypt_store32_le(tag + 12u, w3);

    ctx->finalized = 1;
    scrypt_zeroize(ctx->r, sizeof(ctx->r));
    scrypt_zeroize(ctx->h, sizeof(ctx->h));
    scrypt_zeroize(ctx->pad, sizeof(ctx->pad));
}

void scrypt_poly1305_auth(const uint8_t key[SCRYPT_POLY1305_KEY_SIZE],
                          const uint8_t *msg,
                          size_t len,
                          uint8_t tag[SCRYPT_POLY1305_TAG_SIZE]) {
    scrypt_poly1305_ctx ctx;
    scrypt_poly1305_init(&ctx, key);
    scrypt_poly1305_update(&ctx, msg, len);
    scrypt_poly1305_final(&ctx, tag);
}

void scrypt_poly1305_wipe(scrypt_poly1305_ctx *ctx) {
    scrypt_zeroize(ctx, sizeof(*ctx));
}
