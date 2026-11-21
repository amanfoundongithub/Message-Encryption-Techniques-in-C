#ifndef SCRYPT_INTERNAL_ENDIAN_H
#define SCRYPT_INTERNAL_ENDIAN_H

#include <stdint.h>

static inline uint32_t scrypt_load32_be(const uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           ((uint32_t)b[3]);
}

static inline void scrypt_store32_be(uint8_t b[4], uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static inline uint32_t scrypt_load32_le(const uint8_t b[4]) {
    return ((uint32_t)b[0])       |
           ((uint32_t)b[1] << 8)  |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static inline void scrypt_store32_le(uint8_t b[4], uint32_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static inline uint64_t scrypt_load64_be(const uint8_t b[8]) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}

static inline void scrypt_store64_be(uint8_t b[8], uint64_t v) {
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

static inline void scrypt_store64_le(uint8_t b[8], uint64_t v) {
    for (unsigned i = 0u; i < 8u; i++) {
        b[i] = (uint8_t)(v >> (8u * i));
    }
}

#endif 
