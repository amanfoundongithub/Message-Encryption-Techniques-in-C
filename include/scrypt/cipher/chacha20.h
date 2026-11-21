#ifndef SCRYPT_CIPHER_CHACHA20_H
#define SCRYPT_CIPHER_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_CHACHA20_KEY_SIZE   32u
#define SCRYPT_CHACHA20_NONCE_SIZE 12u
#define SCRYPT_CHACHA20_BLOCK_SIZE 64u

typedef struct {
    uint32_t state[16];
} scrypt_chacha20_ctx;

void scrypt_chacha20_init(scrypt_chacha20_ctx *ctx,
                           const uint8_t key[SCRYPT_CHACHA20_KEY_SIZE],
                           uint32_t counter,
                           const uint8_t nonce[SCRYPT_CHACHA20_NONCE_SIZE]);

void scrypt_chacha20_set_counter(scrypt_chacha20_ctx *ctx, uint32_t counter);

void scrypt_chacha20_block(const scrypt_chacha20_ctx *ctx,
                           uint8_t out[SCRYPT_CHACHA20_BLOCK_SIZE]);

void scrypt_chacha20_xor(scrypt_chacha20_ctx *ctx,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len);

void scrypt_chacha20_wipe(scrypt_chacha20_ctx *ctx);

void scrypt_hchacha20(const uint8_t key[32], const uint8_t nonce16[16], uint8_t subkey[32]);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_CIPHER_CHACHA20_H */
