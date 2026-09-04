#include "hmac_sha256.h"
#include "sha256.h"

#include <stdint.h>
#include <string.h>

#define HMAC_SHA256_BLOCK_SIZE 64
#define HMAC_SHA256_DIGEST_SIZE 32

size_t hmac_sha256(
    const void* key,
    size_t keylen,
    const void* data,
    size_t datalen,
    void* out,
    size_t outlen
)
{
    uint8_t k[HMAC_SHA256_BLOCK_SIZE];
    uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t keyHash[HMAC_SHA256_DIGEST_SIZE];
    uint8_t innerHash[HMAC_SHA256_DIGEST_SIZE];
    uint8_t outerHash[HMAC_SHA256_DIGEST_SIZE];

    memset(k, 0, sizeof(k));

    if (keylen > HMAC_SHA256_BLOCK_SIZE)
    {
        SHA256_CTX ctx;

        sha256_init(&ctx);
        sha256_update(
            &ctx,
            static_cast<const BYTE*>(key),
            keylen
        );
        sha256_final(&ctx, keyHash);

        memcpy(k, keyHash, HMAC_SHA256_DIGEST_SIZE);
    }
    else if (keylen > 0)
    {
        memcpy(k, key, keylen);
    }

    for (size_t i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    SHA256_CTX inner;

    sha256_init(&inner);
    sha256_update(
        &inner,
        ipad,
        HMAC_SHA256_BLOCK_SIZE
    );

    if (datalen > 0)
    {
        sha256_update(
            &inner,
            static_cast<const BYTE*>(data),
            datalen
        );
    }

    sha256_final(&inner, innerHash);

    SHA256_CTX outer;

    sha256_init(&outer);
    sha256_update(
        &outer,
        opad,
        HMAC_SHA256_BLOCK_SIZE
    );
    sha256_update(
        &outer,
        innerHash,
        HMAC_SHA256_DIGEST_SIZE
    );
    sha256_final(&outer, outerHash);

    size_t written =
        outlen < HMAC_SHA256_DIGEST_SIZE
        ? outlen
        : HMAC_SHA256_DIGEST_SIZE;

    if (written > 0)
        memcpy(out, outerHash, written);

    return written;
}
