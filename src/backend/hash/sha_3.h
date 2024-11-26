#ifndef SHA3_H
#define SHA3_H

#include "common.h"

#define L 6
#define W 64
#define B 1600
#define Nr 24

typedef struct sha_3_ctx
{
    union
    {
        uint8_t b[B / 8]; // in 8-bit bytes
        uint64_t q[25];   // in 64-bit words
    } state;
    unsigned int cnt;    // byte counter
    unsigned int rate;   // in 8-bit bytes
    unsigned int md_len; // in 8-bit bytes
} sha3_ctx_t;

// Keccak-f[b] permutation
void sha3_keccakf(uint64_t st[25]);

// SHA3
void sha3_init(sha3_ctx_t *ctx, int md_len);
void sha3_update(sha3_ctx_t *ctx, const void *m, size_t len);
void sha3_final(void *md, sha3_ctx_t *ctx);
void *sha3(const void *m, size_t len, void *md, int md_len);

// SHAKE
#define shake128_init(ctx) sha3_init(ctx, 16)
#define shake256_init(ctx) sha3_init(ctx, 32)
#define shake_update sha3_update

void shake_xof(sha3_ctx_t *c);
void *shake_out(sha3_ctx_t *c, void *out, size_t len);

#endif