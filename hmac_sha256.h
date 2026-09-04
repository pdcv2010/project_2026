#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t hmac_sha256(
    const void* key,
    size_t keylen,
    const void* data,
    size_t datalen,
    void* out,
    size_t outlen
);

#ifdef __cplusplus
}
#endif

#endif
