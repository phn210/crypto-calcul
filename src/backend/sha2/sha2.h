#ifndef SHA2_H
#define SHA2_H

#include "common.h"

#define SHA224_DIGEST_SIZE (224 / 8)
#define SHA256_DIGEST_SIZE (256 / 8)
#define SHA384_DIGEST_SIZE (384 / 8)
#define SHA512_DIGEST_SIZE (512 / 8)

#define SHA256_BLOCK_SIZE (512 / 8)
#define SHA512_BLOCK_SIZE (1024 / 8)
#define SHA384_BLOCK_SIZE SHA512_BLOCK_SIZE
#define SHA224_BLOCK_SIZE SHA256_BLOCK_SIZE

#ifndef SHA2_TYPES
#define SHA2_TYPES
typedef unsigned char uint8;
typedef unsigned int uint32;
typedef uint64_t uint64;
#endif

typedef struct
{
    uint64 tot_len;
    uint64 len;
    uint8 block[2 * SHA256_BLOCK_SIZE];
    uint32 h[8];
} sha256_ctx;

typedef struct
{
    uint64 tot_len;
    uint64 len;
    uint8 block[2 * SHA512_BLOCK_SIZE];
    uint64 h[8];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;
typedef sha256_ctx sha224_ctx;

void sha224_init(sha224_ctx *ctx);
void sha224_update(sha224_ctx *ctx, const uint8 *message, uint64 len);
void sha224_final(sha224_ctx *ctx, uint8 *digest);
void sha224(const uint8 *message, uint64 len, uint8 *digest);

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8 *message, uint64 len);
void sha256_final(sha256_ctx *ctx, uint8 *digest);
void sha256(const uint8 *message, uint64 len, uint8 *digest);

void sha384_init(sha384_ctx *ctx);
void sha384_update(sha384_ctx *ctx, const uint8 *message, uint64 len);
void sha384_final(sha384_ctx *ctx, uint8 *digest);
void sha384(const uint8 *message, uint64 len, uint8 *digest);

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8 *message, uint64 len);
void sha512_final(sha512_ctx *ctx, uint8 *digest);
void sha512(const uint8 *message, uint64 len, uint8 *digest);

void *sha2(const void *m, size_t len, void *md, size_t md_len);

#endif
