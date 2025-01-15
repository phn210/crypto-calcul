
#ifndef MD5_H
#define MD5_H

#include "common.h"

#define MD5_BLOCK_SIZE 16 // MD5 outputs a 16 byte digest
#define MD5_DIGEST_SIZE 16

typedef struct
{
    BYTE data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[4];
} md5_ctx;

void md5_init(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, const BYTE data[], size_t len);
void md5_final(md5_ctx *ctx, BYTE hash[]);

void *md5(const void *m, size_t len, void *md, size_t md_len);

#endif
