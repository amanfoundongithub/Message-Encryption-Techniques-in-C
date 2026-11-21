#ifndef SCRYPT_HASH_SHA256_H
#define SCRYPT_HASH_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_SHA256_DIGEST_SIZE 32u
#define SCRYPT_SHA256_BLOCK_SIZE  64u

typedef struct {
    uint32_t state[8];
    uint64_t count;               /* Number of bytes processed */
    uint8_t  buffer[SCRYPT_SHA256_BLOCK_SIZE];
} scrypt_sha256_ctx;

void scrypt_sha256_init(scrypt_sha256_ctx *ctx);
void scrypt_sha256_update(scrypt_sha256_ctx *ctx, const void *data, size_t len);
void scrypt_sha256_final(scrypt_sha256_ctx *ctx, uint8_t digest[SCRYPT_SHA256_DIGEST_SIZE]);
void scrypt_sha256(const void *data, size_t len, uint8_t digest[SCRYPT_SHA256_DIGEST_SIZE]);
void scrypt_sha256_wipe(scrypt_sha256_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_HASH_SHA256_H */
