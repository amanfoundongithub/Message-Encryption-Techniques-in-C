#include "scrypt/cipher/aes.h"
#include "internal/endian.h"
#include "internal/zeroize.h"
#include <string.h>

static const uint8_t AES_SBOX[256] = {
    0x63u, 0x7cu, 0x77u, 0x7bu, 0xf2u, 0x6bu, 0x6fu, 0xc5u, 0x30u, 0x01u, 0x67u, 0x2bu, 0xfeu, 0xd7u, 0xabu, 0x76u,
    0xcau, 0x82u, 0xc9u, 0x7du, 0xfau, 0x59u, 0x47u, 0xf0u, 0xadu, 0xd4u, 0xa2u, 0xafu, 0x9cu, 0xa4u, 0x72u, 0xc0u,
    0xb7u, 0xfdu, 0x93u, 0x26u, 0x36u, 0x3fu, 0xf7u, 0xccu, 0x34u, 0xa5u, 0xe5u, 0xf1u, 0x71u, 0xd8u, 0x31u, 0x15u,
    0x04u, 0xc7u, 0x23u, 0xc3u, 0x18u, 0x96u, 0x05u, 0x9au, 0x07u, 0x12u, 0x80u, 0xe2u, 0xebu, 0x27u, 0xb2u, 0x75u,
    0x09u, 0x83u, 0x2cu, 0x1au, 0x1bu, 0x6eu, 0x5au, 0xa0u, 0x52u, 0x3bu, 0xd6u, 0xb3u, 0x29u, 0xe3u, 0x2fu, 0x84u,
    0x53u, 0xd1u, 0x00u, 0xedu, 0x20u, 0xfcu, 0xb1u, 0x5bu, 0x6au, 0xcbu, 0xbeu, 0x39u, 0x4au, 0x4cu, 0x58u, 0xcfu,
    0xd0u, 0xefu, 0xaau, 0xfbu, 0x43u, 0x4du, 0x33u, 0x85u, 0x45u, 0xf9u, 0x02u, 0x7fu, 0x50u, 0x3cu, 0x9fu, 0xa8u,
    0x51u, 0xa3u, 0x40u, 0x8fu, 0x92u, 0x9du, 0x38u, 0xf5u, 0xbcu, 0xb6u, 0xdau, 0x21u, 0x10u, 0xffu, 0xf3u, 0xd2u,
    0xcdu, 0x0cu, 0x13u, 0xecu, 0x5fu, 0x97u, 0x44u, 0x17u, 0xc4u, 0xa7u, 0x7eu, 0x3du, 0x64u, 0x5du, 0x19u, 0x73u,
    0x60u, 0x81u, 0x4fu, 0xdcu, 0x22u, 0x2au, 0x90u, 0x88u, 0x46u, 0xeeu, 0xb8u, 0x14u, 0xdeu, 0x5eu, 0x0bu, 0xdbu,
    0xe0u, 0x32u, 0x3au, 0x0au, 0x49u, 0x06u, 0x24u, 0x5cu, 0xc2u, 0xd3u, 0xacu, 0x62u, 0x91u, 0x95u, 0xe4u, 0x79u,
    0xe7u, 0xc8u, 0x37u, 0x6du, 0x8du, 0xd5u, 0x4eu, 0xa9u, 0x6cu, 0x56u, 0xf4u, 0xeau, 0x65u, 0x7au, 0xaeu, 0x08u,
    0xbau, 0x78u, 0x25u, 0x2eu, 0x1cu, 0xa6u, 0xb4u, 0xc6u, 0xe8u, 0xddu, 0x74u, 0x1fu, 0x4bu, 0xbdu, 0x8bu, 0x8au,
    0x70u, 0x3eu, 0xb5u, 0x66u, 0x48u, 0x03u, 0xf6u, 0x0eu, 0x61u, 0x35u, 0x57u, 0xb9u, 0x86u, 0xc1u, 0x1du, 0x9eu,
    0xe1u, 0xf8u, 0x98u, 0x11u, 0x69u, 0xd9u, 0x8eu, 0x94u, 0x9bu, 0x1eu, 0x87u, 0xe9u, 0xceu, 0x55u, 0x28u, 0xdfu,
    0x8cu, 0xa1u, 0x89u, 0x0du, 0xbfu, 0xe6u, 0x42u, 0x68u, 0x41u, 0x99u, 0x2du, 0x0fu, 0xb0u, 0x54u, 0xbbu, 0x16u
};

static const uint8_t AES_INV_SBOX[256] = {
    0x52u, 0x09u, 0x6au, 0xd5u, 0x30u, 0x36u, 0xa5u, 0x38u, 0xbfu, 0x40u, 0xa3u, 0x9eu, 0x81u, 0xf3u, 0xd7u, 0xfbu,
    0x7cu, 0xe3u, 0x39u, 0x82u, 0x9bu, 0x2fu, 0xffu, 0x87u, 0x34u, 0x8eu, 0x43u, 0x44u, 0xc4u, 0xdeu, 0xe9u, 0xcbu,
    0x54u, 0x7bu, 0x94u, 0x32u, 0xa6u, 0xc2u, 0x23u, 0x3du, 0xeeu, 0x4cu, 0x95u, 0x0bu, 0x42u, 0xfau, 0xc3u, 0x4eu,
    0x08u, 0x2eu, 0xa1u, 0x66u, 0x28u, 0xd9u, 0x24u, 0xb2u, 0x76u, 0x5bu, 0xa2u, 0x49u, 0x6du, 0x8bu, 0xd1u, 0x25u,
    0x72u, 0xf8u, 0xf6u, 0x64u, 0x86u, 0x68u, 0x98u, 0x16u, 0xd4u, 0xa4u, 0x5cu, 0xccu, 0x5du, 0x65u, 0xb6u, 0x92u,
    0x6cu, 0x70u, 0x48u, 0x50u, 0xfdu, 0xedu, 0xb9u, 0xdau, 0x5eu, 0x15u, 0x46u, 0x57u, 0xa7u, 0x8du, 0x9du, 0x84u,
    0x90u, 0xd8u, 0xabu, 0x00u, 0x8cu, 0xbcu, 0xd3u, 0x0au, 0xf7u, 0xe4u, 0x58u, 0x05u, 0xb8u, 0xb3u, 0x45u, 0x06u,
    0xd0u, 0x2cu, 0x1eu, 0x8fu, 0xcau, 0x3fu, 0x0fu, 0x02u, 0xc1u, 0xafu, 0xbdu, 0x03u, 0x01u, 0x13u, 0x8au, 0x6bu,
    0x3au, 0x91u, 0x11u, 0x41u, 0x4fu, 0x67u, 0xdcu, 0xeau, 0x97u, 0xf2u, 0xcfu, 0xceu, 0xf0u, 0xb4u, 0xe6u, 0x73u,
    0x96u, 0xacu, 0x74u, 0x22u, 0xe7u, 0xadu, 0x35u, 0x85u, 0xe2u, 0xf9u, 0x37u, 0xe8u, 0x1cu, 0x75u, 0xdfu, 0x6eu,
    0x47u, 0xf1u, 0x1au, 0x71u, 0x1du, 0x29u, 0xc5u, 0x89u, 0x6fu, 0xb7u, 0x62u, 0x0eu, 0xaau, 0x18u, 0xbeu, 0x1bu,
    0xfcu, 0x56u, 0x3eu, 0x4bu, 0xc6u, 0xd2u, 0x79u, 0x20u, 0x9au, 0xdbu, 0xc0u, 0xfeu, 0x78u, 0xcdu, 0x5au, 0xf4u,
    0x1fu, 0xddu, 0xa8u, 0x33u, 0x88u, 0x07u, 0xc7u, 0x31u, 0xb1u, 0x12u, 0x10u, 0x59u, 0x27u, 0x80u, 0xecu, 0x5fu,
    0x60u, 0x51u, 0x7fu, 0xa9u, 0x19u, 0xb5u, 0x4au, 0x0du, 0x2du, 0xe5u, 0x7au, 0x9fu, 0x93u, 0xc9u, 0x9cu, 0xefu,
    0xa0u, 0xe0u, 0x3bu, 0x4du, 0xaeu, 0x2au, 0xf5u, 0xb0u, 0xc8u, 0xebu, 0xbbu, 0x3cu, 0x83u, 0x53u, 0x99u, 0x61u,
    0x17u, 0x2bu, 0x04u, 0x7eu, 0xbau, 0x77u, 0xd6u, 0x26u, 0xe1u, 0x69u, 0x14u, 0x63u, 0x55u, 0x21u, 0x0cu, 0x7du
};

static const uint8_t AES_RCON[10] = {
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u, 0x1bu, 0x36u
};

static inline uint8_t xtime(uint8_t x) {
    uint8_t shifted = (uint8_t)(x << 1);
    return (x & 0x80u) ? (uint8_t)(shifted ^ 0x1bu) : shifted;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    uint8_t factor = a;
    for (unsigned bit = 0; bit < 8u; bit++) {
        if (b & 1u) {
            res ^= factor;
        }
        factor = xtime(factor);
        b >>= 1;
    }
    return res;
}

static inline uint32_t rotl32_8(uint32_t w) {
    return (w << 8) | (w >> 24);
}

static uint32_t sub_word(uint32_t w) {
    uint8_t b0 = AES_SBOX[(w >> 24) & 0xffu];
    uint8_t b1 = AES_SBOX[(w >> 16) & 0xffu];
    uint8_t b2 = AES_SBOX[(w >> 8)  & 0xffu];
    uint8_t b3 = AES_SBOX[w & 0xffu];
    return ((uint32_t)b0 << 24) |
           ((uint32_t)b1 << 16) |
           ((uint32_t)b2 << 8)  |
           ((uint32_t)b3);
}

void scrypt_aes128_init(scrypt_aes128_ctx *ctx,
                        const uint8_t key[SCRYPT_AES128_KEY_SIZE]) {
    for (unsigned i = 0; i < 4u; i++) {
        ctx->round_keys[i] = scrypt_load32_be(key + i * 4u);
    }

    for (unsigned i = 4u; i < SCRYPT_AES128_ROUND_WORDS; i++) {
        uint32_t temp = ctx->round_keys[i - 1u];
        if ((i % 4u) == 0u) {
            uint32_t rcon = (uint32_t)AES_RCON[(i / 4u) - 1u] << 24;
            temp = sub_word(rotl32_8(temp)) ^ rcon;
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4u] ^ temp;
    }
}

/* State is a 4x4 matrix indexed as state[row * 4 + col] (FIPS 197 column-major input) */
static void add_round_key(uint8_t state[16], const uint32_t rk[4]) {
    for (unsigned col = 0; col < 4u; col++) {
        uint32_t w = rk[col];
        state[0u * 4u + col] ^= (uint8_t)(w >> 24);
        state[1u * 4u + col] ^= (uint8_t)(w >> 16);
        state[2u * 4u + col] ^= (uint8_t)(w >> 8);
        state[3u * 4u + col] ^= (uint8_t)(w);
    }
}

static void sub_bytes(uint8_t state[16]) {
    for (unsigned i = 0; i < 16u; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (unsigned i = 0; i < 16u; i++) {
        state[i] = AES_INV_SBOX[state[i]];
    }
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16u);

    /* Row 0: unchanged */
    /* Row 1: shift left by 1 */
    state[1u * 4u + 0u] = tmp[1u * 4u + 1u];
    state[1u * 4u + 1u] = tmp[1u * 4u + 2u];
    state[1u * 4u + 2u] = tmp[1u * 4u + 3u];
    state[1u * 4u + 3u] = tmp[1u * 4u + 0u];

    /* Row 2: shift left by 2 */
    state[2u * 4u + 0u] = tmp[2u * 4u + 2u];
    state[2u * 4u + 1u] = tmp[2u * 4u + 3u];
    state[2u * 4u + 2u] = tmp[2u * 4u + 0u];
    state[2u * 4u + 3u] = tmp[2u * 4u + 1u];

    /* Row 3: shift left by 3 (right by 1) */
    state[3u * 4u + 0u] = tmp[3u * 4u + 3u];
    state[3u * 4u + 1u] = tmp[3u * 4u + 0u];
    state[3u * 4u + 2u] = tmp[3u * 4u + 1u];
    state[3u * 4u + 3u] = tmp[3u * 4u + 2u];
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16u);

    /* Row 0: unchanged */
    /* Row 1: shift right by 1 */
    state[1u * 4u + 0u] = tmp[1u * 4u + 3u];
    state[1u * 4u + 1u] = tmp[1u * 4u + 0u];
    state[1u * 4u + 2u] = tmp[1u * 4u + 1u];
    state[1u * 4u + 3u] = tmp[1u * 4u + 2u];

    /* Row 2: shift right by 2 */
    state[2u * 4u + 0u] = tmp[2u * 4u + 2u];
    state[2u * 4u + 1u] = tmp[2u * 4u + 3u];
    state[2u * 4u + 2u] = tmp[2u * 4u + 0u];
    state[2u * 4u + 3u] = tmp[2u * 4u + 1u];

    /* Row 3: shift right by 3 (left by 1) */
    state[3u * 4u + 0u] = tmp[3u * 4u + 1u];
    state[3u * 4u + 1u] = tmp[3u * 4u + 2u];
    state[3u * 4u + 2u] = tmp[3u * 4u + 3u];
    state[3u * 4u + 3u] = tmp[3u * 4u + 0u];
}

static void mix_columns(uint8_t state[16]) {
    for (unsigned col = 0; col < 4u; col++) {
        uint8_t s0 = state[0u * 4u + col];
        uint8_t s1 = state[1u * 4u + col];
        uint8_t s2 = state[2u * 4u + col];
        uint8_t s3 = state[3u * 4u + col];

        state[0u * 4u + col] = (uint8_t)(xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3);
        state[1u * 4u + col] = (uint8_t)(s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3);
        state[2u * 4u + col] = (uint8_t)(s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3);
        state[3u * 4u + col] = (uint8_t)(xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3));
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (unsigned col = 0; col < 4u; col++) {
        uint8_t s0 = state[0u * 4u + col];
        uint8_t s1 = state[1u * 4u + col];
        uint8_t s2 = state[2u * 4u + col];
        uint8_t s3 = state[3u * 4u + col];

        state[0u * 4u + col] = (uint8_t)(gf_mul(0x0eu, s0) ^ gf_mul(0x0bu, s1) ^ gf_mul(0x0du, s2) ^ gf_mul(0x09u, s3));
        state[1u * 4u + col] = (uint8_t)(gf_mul(0x09u, s0) ^ gf_mul(0x0eu, s1) ^ gf_mul(0x0bu, s2) ^ gf_mul(0x0du, s3));
        state[2u * 4u + col] = (uint8_t)(gf_mul(0x0du, s0) ^ gf_mul(0x09u, s1) ^ gf_mul(0x0eu, s2) ^ gf_mul(0x0bu, s3));
        state[3u * 4u + col] = (uint8_t)(gf_mul(0x0bu, s0) ^ gf_mul(0x0du, s1) ^ gf_mul(0x09u, s2) ^ gf_mul(0x0eu, s3));
    }
}

static void load_state_col_major(uint8_t state[16], const uint8_t in[16]) {
    for (unsigned col = 0; col < 4u; col++) {
        for (unsigned row = 0; row < 4u; row++) {
            state[row * 4u + col] = in[col * 4u + row];
        }
    }
}

static void store_state_col_major(uint8_t out[16], const uint8_t state[16]) {
    for (unsigned col = 0; col < 4u; col++) {
        for (unsigned row = 0; row < 4u; row++) {
            out[col * 4u + row] = state[row * 4u + col];
        }
    }
}

void scrypt_aes128_encrypt_block(const scrypt_aes128_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES_BLOCK_SIZE]) {
    uint8_t state[16];
    load_state_col_major(state, in);

    add_round_key(state, &ctx->round_keys[0]);

    for (unsigned round = 1u; round < SCRYPT_AES128_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4u]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[SCRYPT_AES128_ROUNDS * 4u]);

    store_state_col_major(out, state);
    scrypt_zeroize(state, sizeof(state));
}

void scrypt_aes128_decrypt_block(const scrypt_aes128_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES_BLOCK_SIZE]) {
    uint8_t state[16];
    load_state_col_major(state, in);

    add_round_key(state, &ctx->round_keys[SCRYPT_AES128_ROUNDS * 4u]);

    for (unsigned round = SCRYPT_AES128_ROUNDS - 1u; round >= 1u; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx->round_keys[round * 4u]);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ctx->round_keys[0]);

    store_state_col_major(out, state);
    scrypt_zeroize(state, sizeof(state));
}

void scrypt_aes128_wipe(scrypt_aes128_ctx *ctx) {
    scrypt_zeroize(ctx, sizeof(*ctx));
}
