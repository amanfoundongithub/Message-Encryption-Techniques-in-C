#ifndef SCRYPT_INTERNAL_ZEROIZE_H
#define SCRYPT_INTERNAL_ZEROIZE_H

#include <stddef.h>
#include <stdint.h>

static inline void scrypt_zeroize(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

#endif