#include "sha_3.h"

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

static const uint64_t keccakf_rndc[Nr] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

static const unsigned keccakf_rotc[Nr] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

void sha3_keccakf(uint64_t st[25])
{
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < Nr; r++)
    {
        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho & Pi
        t = st[1];
        for (i = 0; i < 24; i++)
        {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

void sha3_init(sha3_ctx_t *ctx, size_t md_len)
{
    int i;
    for (i = 0; i < 25; i++)
        ctx->state.q[i] = 0;
    ctx->md_len = md_len;
    ctx->rate = 200 - 2 * md_len;
    ctx->cnt = 0;
}

void sha3_update(sha3_ctx_t *ctx, const void *m, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        ctx->state.b[ctx->cnt++] ^= ((const uint8_t *)m)[i];
        if (ctx->cnt >= ctx->rate)
        {
            sha3_keccakf(ctx->state.q);
            ctx->cnt = 0;
        }
    }
}

void sha3_final(void *md, sha3_ctx_t *ctx)
{
    ctx->state.b[ctx->cnt] ^= 0x06;
    ctx->state.b[ctx->rate - 1] ^= 0x80;
    sha3_keccakf(ctx->state.q);
    memcpy(md, ctx->state.b, ctx->md_len);
}

void *sha3(const void *m, size_t len, void *md, size_t md_len)
{
    sha3_ctx_t ctx;
    sha3_init(&ctx, md_len);
    sha3_update(&ctx, m, len);
    sha3_final(md, &ctx);
    return md;
}

void shake_xof(sha3_ctx_t *ctx)
{
    ctx->state.b[ctx->cnt] ^= 0x1F;
    ctx->state.b[ctx->rate - 1] ^= 0x80;
    sha3_keccakf(ctx->state.q);
    ctx->cnt = 0;
}

void *shake_out(sha3_ctx_t *ctx, void *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        if (ctx->cnt >= ctx->rate)
        {
            sha3_keccakf(ctx->state.q);
            ctx->cnt = 0;
        }
        ((uint8_t *)out)[i] = ctx->state.b[ctx->cnt++];
    }
    return out;
}