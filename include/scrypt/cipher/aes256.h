#ifndef SCRYPT_CIPHER_AES256_H
#define SCRYPT_CIPHER_AES256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_AES256_BLOCK_SIZE     16u
#define SCRYPT_AES256_KEY_SIZE       32u
#define SCRYPT_AES256_ROUNDS         14u
#define SCRYPT_AES256_ROUND_WORDS    60u /* 4 words * (14 rounds + 1) */

typedef struct {
    uint32_t round_keys[SCRYPT_AES256_ROUND_WORDS];
} scrypt_aes256_ctx;

void scrypt_aes256_init(scrypt_aes256_ctx *ctx,
                        const uint8_t key[SCRYPT_AES256_KEY_SIZE]);

void scrypt_aes256_encrypt_block(const scrypt_aes256_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES256_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES256_BLOCK_SIZE]);

void scrypt_aes256_decrypt_block(const scrypt_aes256_ctx *ctx,
                                 const uint8_t in[SCRYPT_AES256_BLOCK_SIZE],
                                 uint8_t out[SCRYPT_AES256_BLOCK_SIZE]);

void scrypt_aes256_wipe(scrypt_aes256_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_CIPHER_AES256_H */
