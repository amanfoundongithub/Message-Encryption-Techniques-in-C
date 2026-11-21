#ifndef SCRYPT_MODE_AES_CTR_H
#define SCRYPT_MODE_AES_CTR_H

#include "scrypt/cipher/aes.h"
#include "scrypt/cipher/aes256.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_AES_CTR_IV_SIZE    16u
#define SCRYPT_AES_CTR_BLOCK_SIZE 16u

typedef struct {
    scrypt_aes128_ctx cipher;
    uint8_t           counter[SCRYPT_AES_CTR_IV_SIZE];
    uint8_t           keystream[SCRYPT_AES_CTR_BLOCK_SIZE];
    size_t            ks_offset;
} scrypt_aes128_ctr_ctx;

typedef struct {
    scrypt_aes256_ctx cipher;
    uint8_t           counter[SCRYPT_AES_CTR_IV_SIZE];
    uint8_t           keystream[SCRYPT_AES_CTR_BLOCK_SIZE];
    size_t            ks_offset;
} scrypt_aes256_ctr_ctx;

void scrypt_aes128_ctr_init(scrypt_aes128_ctr_ctx *ctx,
                            const uint8_t key[SCRYPT_AES128_KEY_SIZE],
                            const uint8_t iv[SCRYPT_AES_CTR_IV_SIZE]);

void scrypt_aes128_ctr_xor(scrypt_aes128_ctr_ctx *ctx,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t len);

void scrypt_aes128_ctr_wipe(scrypt_aes128_ctr_ctx *ctx);

void scrypt_aes256_ctr_init(scrypt_aes256_ctr_ctx *ctx,
                            const uint8_t key[SCRYPT_AES256_KEY_SIZE],
                            const uint8_t iv[SCRYPT_AES_CTR_IV_SIZE]);

void scrypt_aes256_ctr_xor(scrypt_aes256_ctr_ctx *ctx,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t len);

void scrypt_aes256_ctr_wipe(scrypt_aes256_ctr_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_MODE_AES_CTR_H */
