#ifndef SCRYPT_MAC_POLY1305_H
#define SCRYPT_MAC_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_POLY1305_KEY_SIZE 32u
#define SCRYPT_POLY1305_TAG_SIZE 16u

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buf[16];
    size_t   buf_len;
    int      finalized;
} scrypt_poly1305_ctx;

void scrypt_poly1305_init(scrypt_poly1305_ctx *ctx,
                            const uint8_t key[SCRYPT_POLY1305_KEY_SIZE]);

void scrypt_poly1305_update(scrypt_poly1305_ctx *ctx,
                              const uint8_t *msg,
                              size_t len);

/* Pads any partial block with zeros to a 16-byte boundary (used by AEAD) */
void scrypt_poly1305_pad16(scrypt_poly1305_ctx *ctx);

void scrypt_poly1305_final(scrypt_poly1305_ctx *ctx,
                             uint8_t tag[SCRYPT_POLY1305_TAG_SIZE]);

void scrypt_poly1305_auth(const uint8_t key[SCRYPT_POLY1305_KEY_SIZE],
                          const uint8_t *msg,
                          size_t len,
                          uint8_t tag[SCRYPT_POLY1305_TAG_SIZE]);

void scrypt_poly1305_wipe(scrypt_poly1305_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_MAC_POLY1305_H */
