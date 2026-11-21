#ifndef SCRYPT_CIPHER_AES_H
#define SCRYPT_CIPHER_AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_AES_BLOCK_SIZE     16u
#define SCRYPT_AES128_KEY_SIZE    16u
#define SCRYPT_AES128_ROUNDS      10u
#define SCRYPT_AES128_ROUND_WORDS 44u /* 4 words * (10 rounds + 1) */

typedef struct {
    uint32_t round_keys[SCRYPT_AES128_ROUND_WORDS];
} scrypt_aes128_ctx;

void scrypt_aes128_init(scrypt_aes128_ctx *ctx,
                        const uint8_t key[SCRYPT_AES128_KEY_SIZE]);

void scrypt_aes128_encrypt_block(const scrypt_aes128_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES_BLOCK_SIZE]);

void scrypt_aes128_decrypt_block(const scrypt_aes128_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES_BLOCK_SIZE]);

void scrypt_aes128_wipe(scrypt_aes128_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_CIPHER_AES_H */
