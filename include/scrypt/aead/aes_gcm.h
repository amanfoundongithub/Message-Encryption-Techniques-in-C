#ifndef SCRYPT_AEAD_AES_GCM_H
#define SCRYPT_AEAD_AES_GCM_H

#include "scrypt/cipher/aes.h"
#include "scrypt/cipher/aes256.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_AES_GCM_TAG_SIZE 16u

#define SCRYPT_GCM_OK        0
#define SCRYPT_GCM_ERR_AUTH  (-1)
#define SCRYPT_GCM_ERR_PARAM (-2)

int scrypt_aes128_gcm_encrypt(const uint8_t key[16],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext,
                              uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE]);

int scrypt_aes128_gcm_decrypt(const uint8_t key[16],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              const uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE],
                              uint8_t *plaintext);

int scrypt_aes256_gcm_encrypt(const uint8_t key[32],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext,
                              uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE]);

int scrypt_aes256_gcm_decrypt(const uint8_t key[32],
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              const uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE],
                              uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
