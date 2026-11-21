#ifndef SCRYPT_CIPHER_DES_H
#define SCRYPT_CIPHER_DES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_DES_BLOCK_SIZE 8u
#define SCRYPT_DES_KEY_SIZE   8u
#define SCRYPT_DES_ROUNDS     16u

typedef struct {
    uint64_t subkeys[SCRYPT_DES_ROUNDS];
} scrypt_des_ctx;

void scrypt_des_init(scrypt_des_ctx *ctx, const uint8_t key[SCRYPT_DES_KEY_SIZE]);
void scrypt_des_encrypt_block(const scrypt_des_ctx *ctx, const uint8_t in[SCRYPT_DES_BLOCK_SIZE], uint8_t out[SCRYPT_DES_BLOCK_SIZE]);
void scrypt_des_decrypt_block(const scrypt_des_ctx *ctx, const uint8_t in[SCRYPT_DES_BLOCK_SIZE], uint8_t out[SCRYPT_DES_BLOCK_SIZE]);
void scrypt_des_wipe(scrypt_des_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif 