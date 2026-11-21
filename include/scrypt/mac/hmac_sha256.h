#ifndef SCRYPT_MAC_HMAC_SHA256_H
#define SCRYPT_MAC_HMAC_SHA256_H

#include "scrypt/hash/sha256.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_HMAC_SHA256_DIGEST_SIZE SCRYPT_SHA256_DIGEST_SIZE
#define SCRYPT_HMAC_SHA256_BLOCK_SIZE  SCRYPT_SHA256_BLOCK_SIZE

typedef struct {
    scrypt_sha256_ctx inner;
    scrypt_sha256_ctx outer;
} scrypt_hmac_sha256_ctx;

void scrypt_hmac_sha256_init(scrypt_hmac_sha256_ctx *ctx,
                               const uint8_t *key,
                               size_t key_len);

void scrypt_hmac_sha256_update(scrypt_hmac_sha256_ctx *ctx,
                                 const void *data,
                                 size_t len);

void scrypt_hmac_sha256_final(scrypt_hmac_sha256_ctx *ctx,
                                uint8_t mac[SCRYPT_HMAC_SHA256_DIGEST_SIZE]);

void scrypt_hmac_sha256(const uint8_t *key,
                          size_t key_len,
                          const void *data,
                          size_t len,
                          uint8_t mac[SCRYPT_HMAC_SHA256_DIGEST_SIZE]);

void scrypt_hmac_sha256_wipe(scrypt_hmac_sha256_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_MAC_HMAC_SHA256_H */
