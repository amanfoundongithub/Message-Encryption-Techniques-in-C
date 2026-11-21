#ifndef SCRYPT_AEAD_CHACHA20_POLY1305_H
#define SCRYPT_AEAD_CHACHA20_POLY1305_H

#include "scrypt/cipher/chacha20.h"
#include "scrypt/mac/poly1305.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_CHACHA20_POLY1305_KEY_SIZE   32u
#define SCRYPT_CHACHA20_POLY1305_NONCE_SIZE 12u
#define SCRYPT_CHACHA20_POLY1305_TAG_SIZE   16u

#define SCRYPT_AEAD_OK       0
#define SCRYPT_AEAD_ERR_AUTH (-1)

void scrypt_chacha20_poly1305_encrypt(
    const uint8_t key[SCRYPT_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[SCRYPT_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *ciphertext,
    uint8_t tag[SCRYPT_CHACHA20_POLY1305_TAG_SIZE]);

int scrypt_chacha20_poly1305_decrypt(
    const uint8_t key[SCRYPT_CHACHA20_POLY1305_KEY_SIZE],
    const uint8_t nonce[SCRYPT_CHACHA20_POLY1305_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ct_len,
    const uint8_t tag[SCRYPT_CHACHA20_POLY1305_TAG_SIZE],
    uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_AEAD_CHACHA20_POLY1305_H */
