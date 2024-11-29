#include "sha_1.h"

#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

void sha1_transform(sha1_ctx_t *ctx, const void *data)
{
    uint32_t a, b, c, d, e, i, j, t, m[80];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (((const uint8_t *)data)[j] << 24) |
               (((const uint8_t *)data)[j + 1] << 16) |
               (((const uint8_t *)data)[j + 2] << 8) |
               (((const uint8_t *)data)[j + 3]);
    for (; i < 80; ++i)
        m[i] = ROTLEFT(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1);
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; ++i)
    {
        if (i < 20)
        {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + m[i] + 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            t = ROTLEFT(a, 5) + ((b & c) | (b & d) | (c & d)) + e + m[i] + 0x8F1BBCDC;
        }
        else
        {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + m[i] + 0xCA62C1D6;
        }
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(sha1_ctx_t *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void sha1_update(sha1_ctx_t *ctx, const void *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = ((const uint8_t *)data)[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(sha1_ctx_t *ctx, void *md)
{
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha1_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i)
    {
        ((uint8_t *)md)[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        ((uint8_t *)md)[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        ((uint8_t *)md)[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        ((uint8_t *)md)[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        ((uint8_t *)md)[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    }
}

void *sha1(const void *data, size_t len, void *md, int md_len)
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, md);
    return md;
}