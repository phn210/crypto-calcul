#include "des.h"

void des_ip(uint64_t *block)
{
    uint64_t new_block = 0;
    for (int i = 0; i < DES_IP_SIZE; i++)
    {
        uint64_t bit = (*block >> (64 - des_ip[i])) & 1;
        new_block |= bit << (64 - i - 1);
    }
    *block = new_block;
}

void des_pi(uint64_t *block)
{
    uint64_t new_block = 0;
    for (int i = 0; i < DES_PI_SIZE; i++)
    {
        uint64_t bit = (*block >> (64 - des_pi[i])) & 1;
        new_block |= bit << (64 - i - 1);
    }
    *block = new_block;
}

void des_fp(uint32_t *subblock)
{
    uint32_t new_subblock = 0;
    for (int i = 0; i < DES_P_SIZE; i++)
    {
        uint32_t bit = (*subblock >> (32 - des_p[i])) & 1;
        new_subblock |= bit << (32 - i - 1);
    }
    *subblock = new_subblock;
}

void des_fexpand(uint32_t *subblock, uint48_t *new_subblock)
{
    uint48_t new_block = 0;
    for (int i = 0; i < DES_E_SIZE; i++)
    {
        uint48_t bit = (*subblock >> (32 - des_e[i])) & 1;
        new_block |= bit << (48 - i - 1);
    }
    *new_subblock = new_block;
}

void des_feistel(uint64_t *block, des_ctx_t *ctx)
{
    uint32_t l = *block >> 32;
    uint32_t r = *block & 0xFFFFFFFF;

    for(int i = 0; i < DES_ROUNDS; i++)
    {
        uint32_t new_r = l ^ des_ffunc(r, ctx->keys[i]);
        l = r;
        r = new_r;
    }
}

void des_sbox(uint48_t *subblock, uint32_t *res_subblock)
{
    uint32_t new_subblock = 0;
    for (int i = 0; i < 8; i++)
    {
        uint8_t s_input = ((*subblock >> (48 - 6 * (i + 1))) & 0x3F);
        uint8_t row = ((s_input & 0x20) >> 4) | (s_input & 1);
        uint8_t col = (s_input >> 1) & 0xF;
        uint8_t s_output = des_sbox[i][row][col];
        new_subblock |= s_output << (32 - 4 * (i + 1));
    }
    *res_subblock = new_subblock;
}

void des_ffunc(uint32_t *subblock, const uint64_t subkey)
{
    uint48_t expanded_subblock;
    des_fexpand(subblock, &expanded_subblock);
    expanded_subblock ^= subkey;
    des_sbox(&expanded_subblock, subblock);
    des_fp(subblock);
}

void des_key_schedule(const uint64_t key, des_ctx_t *ctx)
{
    uint64_t pc1_key = 0;
    for (int i = 0; i < 56; i++)
    {
        uint64_t bit = (key >> (64 - des_pc1[i])) & 1;
        pc1_key |= bit << (56 - i - 1);
    }

    // Split key into two 28-bit halves
    uint32_t c = pc1_key >> 28;
    uint32_t d = pc1_key & 0xFFFFFFF;

    for (int i = 0; i < DES_ROUNDS; i++)
    {
        c = ((c << des_shifts[i]) | (c >> (28 - des_shifts[i]))) & 0xFFFFFFF;
        d = ((d << des_shifts[i]) | (d >> (28 - des_shifts[i]))) & 0xFFFFFFF;

        uint64_t cd = ((uint64_t)c << 28) | d;
        uint64_t subkey = 0;
        for (int j = 0; j < 48; j++)
        {
            uint64_t bit = (cd >> (56 - des_pc2[j])) & 1;
            subkey |= bit << (48 - j - 1);
        }
        ctx->keys[i] = subkey;
    }
}

void des(char *input, char *output, const uint64_t key, const size_t len)
{
    des_ctx_t ctx;
    des_key_schedule(&ctx, key);

    for (int i = 0; i < len; i += 8)
    {
        uint64_t block = 0;
        memcpy(&block, input + i, 8);
        des_ip(&block);
        des_feistel(&block, &ctx);
        des_pi(&block);
        memcpy(output + i, &block, 8);
    }
}