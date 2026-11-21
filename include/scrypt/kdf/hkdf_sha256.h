#ifndef SCRYPT_KDF_HKDF_SHA256_H
#define SCRYPT_KDF_HKDF_SHA256_H

#include "scrypt/mac/hmac_sha256.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCRYPT_HKDF_SHA256_HASH_LEN SCRYPT_HMAC_SHA256_DIGEST_SIZE
#define SCRYPT_HKDF_SHA256_MAX_OKM  (255u * SCRYPT_HKDF_SHA256_HASH_LEN)

#define SCRYPT_HKDF_OK        0
#define SCRYPT_HKDF_ERR_PARAM (-1)

void scrypt_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t prk[SCRYPT_HKDF_SHA256_HASH_LEN]);

int scrypt_hkdf_sha256_expand(const uint8_t prk[SCRYPT_HKDF_SHA256_HASH_LEN],
                             const uint8_t *info, size_t info_len,
                             uint8_t *okm, size_t okm_len);

int scrypt_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_KDF_HKDF_SHA256_H */
