# C Cryptography Toolkit

A portable C99 cryptography library with block ciphers, stream ciphers,
authenticated encryption, message authentication codes, hashes, and key
derivation functions. The public headers use the `scrypt/` include namespace.

> **Security notice:** This project is intended for learning and
> interoperability experiments. It has not been formally audited. Do not use
> it as a replacement for a maintained, security-reviewed cryptography library
> in production systems. DES and unauthenticated modes are included for
> compatibility and educational use, not recommended new deployments.

## Features

### Ciphers

| Implementation | Header | API |
| --- | --- | --- |
| DES, 64-bit block | `include/scrypt/cipher/des.h` | Block encrypt/decrypt |
| AES-128, 128-bit block | `include/scrypt/cipher/aes.h` | Block encrypt/decrypt |
| AES-256, 128-bit block | `include/scrypt/cipher/aes256.h` | Block encrypt/decrypt |
| ChaCha20, 256-bit key | `include/scrypt/cipher/chacha20.h` | Stream XOR and HChaCha20 |

### Modes and authenticated encryption

| Implementation | Header | API |
| --- | --- | --- |
| AES-128 CTR | `include/scrypt/mode/aes_ctr.h` | Streaming XOR |
| AES-256 CTR | `include/scrypt/mode/aes_ctr.h` | Streaming XOR |
| AES-128-GCM | `include/scrypt/aead/aes_gcm.h` | Encrypt/decrypt with authentication |
| AES-256-GCM | `include/scrypt/aead/aes_gcm.h` | Encrypt/decrypt with authentication |
| ChaCha20-Poly1305 | `include/scrypt/aead/chacha20_poly1305.h` | Encrypt/decrypt with authentication |
| XChaCha20-Poly1305 | `include/scrypt/aead/xchacha20_poly1305.h` | Encrypt/decrypt with authentication |

### Hashes, MACs, and KDFs

- SHA-256, including one-shot and streaming APIs
- HMAC-SHA256, including one-shot and streaming APIs
- HKDF-SHA256 with extract and expand operations
- Poly1305, including streaming and one-shot APIs

## Requirements

- A C99 compiler
- `make`
- `ar`

The default build flags target GCC and Clang-compatible compilers. The project
is also compatible with C++ callers through `extern "C"` declarations in its
public headers.

## Build

From the repository root:

```sh
make
```

This creates the static library:

```text
build/libscrypt.a
```

Object files are placed under `build/obj/`.

You can clean generated build products with:

```sh
make clean
```

Use a custom compiler or flags if needed:

```sh
make CC=clang CFLAGS="-std=c99 -O2 -Iinclude -Isrc"
```

## Run the tests

Build and run every test binary:

```sh
make test
```

Individual binaries are generated in `build/bin/`:

```text
build/bin/test_des
build/bin/test_aes
build/bin/test_aes256
build/bin/test_aes_ctr
build/bin/test_aes_gcm
build/bin/test_sha256
build/bin/test_hmac_sha256
build/bin/test_hkdf_sha256
build/bin/test_chacha20
build/bin/test_chacha20_poly1305
build/bin/test_xchacha20_poly1305
```

A sanitizer-focused subset covering DES, AES-128, and SHA-256 is available
with AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
make test-san
```

The test suite includes RFC known-answer tests and authentication tamper checks
where applicable.

## Quick start

### ChaCha20-Poly1305

```c
#include <stdint.h>
#include "scrypt/aead/chacha20_poly1305.h"

int seal_message(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t *plaintext,
                 size_t plaintext_len,
                 const uint8_t *aad,
                 size_t aad_len,
                 uint8_t *ciphertext,
                 uint8_t tag[16])
{
    scrypt_chacha20_poly1305_encrypt(
        key, nonce, aad, aad_len,
        plaintext, plaintext_len, ciphertext, tag);
    return 0;
}

int open_message(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t *ciphertext,
                 size_t ciphertext_len,
                 const uint8_t *aad,
                 size_t aad_len,
                 const uint8_t tag[16],
                 uint8_t *plaintext)
{
    return scrypt_chacha20_poly1305_decrypt(
        key, nonce, aad, aad_len,
        ciphertext, ciphertext_len, tag, plaintext);
}
```

The decryption function returns `SCRYPT_AEAD_OK` on success and
`SCRYPT_AEAD_ERR_AUTH` when authentication fails.

### AES-256-GCM

```c
#include "scrypt/aead/aes_gcm.h"

uint8_t key[32] = {0};       /* Replace with securely generated key bytes. */
uint8_t nonce[12] = {0};     /* Replace with a unique nonce. */
const uint8_t plaintext[] = "Authenticated GCM message";
uint8_t ciphertext[sizeof(plaintext)];
uint8_t tag[SCRYPT_AES_GCM_TAG_SIZE];
uint8_t recovered[sizeof(plaintext)];
const uint8_t aad[] = "header";

int rc = scrypt_aes256_gcm_encrypt(
    key, nonce, sizeof(nonce),
    aad, sizeof(aad) - 1,
    plaintext, sizeof(plaintext) - 1,
    ciphertext, tag);

if (rc == SCRYPT_GCM_OK) {
    rc = scrypt_aes256_gcm_decrypt(
        key, nonce, sizeof(nonce),
        aad, sizeof(aad) - 1,
        ciphertext, sizeof(plaintext) - 1,
        tag, recovered);
}
```

AES-GCM decryption returns `SCRYPT_GCM_OK`, `SCRYPT_GCM_ERR_AUTH`, or
`SCRYPT_GCM_ERR_PARAM`. GCM supports an arbitrary IV length, although a
96-bit IV is recommended for the standard case.

### SHA-256

```c
#include "scrypt/hash/sha256.h"

uint8_t digest[SCRYPT_SHA256_DIGEST_SIZE];
const char message[] = "Hello, world!";

scrypt_sha256(message, sizeof(message) - 1, digest);

/* Streaming alternative */
scrypt_sha256_ctx ctx;
scrypt_sha256_init(&ctx);
scrypt_sha256_update(&ctx, "Hello, ", 7);
scrypt_sha256_update(&ctx, "world!", 6);
scrypt_sha256_final(&ctx, digest);
```

## API reference

All public symbols are prefixed with `scrypt_`, and public headers are located
under `include/scrypt/`.

| Area | Public headers |
| --- | --- |
| Ciphers | `scrypt/cipher/des.h`, `aes.h`, `aes256.h`, `chacha20.h` |
| Modes | `scrypt/mode/aes_ctr.h` |
| AEAD | `scrypt/aead/aes_gcm.h`, `chacha20_poly1305.h`, `xchacha20_poly1305.h` |
| Hash | `scrypt/hash/sha256.h` |
| MAC | `scrypt/mac/hmac_sha256.h`, `poly1305.h` |
| KDF | `scrypt/kdf/hkdf_sha256.h` |

### Common key and nonce sizes

| Primitive | Key | Nonce/IV | Tag |
| --- | ---: | ---: | ---: |
| AES-128 | 16 bytes | 16-byte CTR IV or 12-byte GCM IV | 16-byte GCM tag |
| AES-256 | 32 bytes | 16-byte CTR IV or 12-byte GCM IV | 16-byte GCM tag |
| ChaCha20 | 32 bytes | 12 bytes | - |
| ChaCha20-Poly1305 | 32 bytes | 12 bytes | 16 bytes |
| XChaCha20-Poly1305 | 32 bytes | 24 bytes | 16 bytes |
| HMAC-SHA256 / SHA-256 | variable key | - | 32 bytes |
| Poly1305 | 32 bytes | - | 16 bytes |

## Linking

Compile a program against the static library:

```sh
cc -std=c99 -O2 -Iinclude -Isrc my_program.c build/libscrypt.a -o my_program
```

For projects using the library source directly, compile the C files listed in
the `SRCS` variable in `Makefile` and include the repository's `include/` and
`src/` directories.

## Security considerations

- **Never reuse a nonce or IV with the same key** for AEAD or CTR modes.
- Generate keys and random nonces/IVs with a cryptographically secure random
  source.
- Do not treat ciphertext as authenticated unless an AEAD primitive or a
  separately verified MAC is used.
- Use fresh ciphertext-specific keys or a unique nonce for every encryption.
- Verify authentication tags before decrypting or exposing plaintext.
- Wipe sensitive context structures with the library's `_wipe` functions when
  they are no longer needed. This is best-effort protection and cannot prevent
  copies made elsewhere or memory recovery after process termination.
- DES uses a 56-bit effective key and is deprecated. Use AES or ChaCha20-based
  algorithms for new designs.
- AES-GCM and CTR implementations should be treated as reference
  implementations; they do not imply hardware-backed constant-time guarantees.

## Project structure

```text
include/scrypt/   Public C headers
src/cipher/       DES, AES, AES-256, and ChaCha20 implementations
src/mode/         Counter-mode implementations
src/aead/         GCM and ChaCha20-Poly1305 implementations
src/hash/         SHA-256 implementation
src/mac/          HMAC-SHA256 and Poly1305 implementations
src/kdf/          HKDF-SHA256 implementation
src/internal/     Internal helpers
tests/            Known-answer, round-trip, and tamper tests
Makefile          Static library and test build rules
```

## Standards and test vectors

The implementation and test suite cover, among others:

- AES known-answer tests
- AES-CTR test vectors
- NIST SP 800-38D AES-GCM test cases
- SHA-256 standard and streaming test vectors
- RFC 4231 HMAC-SHA256 test cases
- RFC 5869 HKDF-SHA256 test cases
- RFC 8439 ChaCha20, Poly1305, and ChaCha20-Poly1305 test vectors
- Round-trip and ciphertext-tamper checks for AEAD modes

## Contributing

Contributions are welcome:

1. Create a focused change or bug fix.
2. Add or update a test vector or tamper check for changed behavior.
3. Run `make clean && make test`.
4. Submit a pull request with a concise explanation and test results.

Keep cryptographic changes isolated and reference the relevant standard or
published test vector where possible.

## License

No license file is currently included in this repository. All rights are
reserved by the repository owner unless a license is explicitly added.
