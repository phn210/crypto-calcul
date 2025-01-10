#include "des.h"
#include "conversion.h"

void des_ip(uint64_t *block)
{
    uint64_t new_block = 0;
    for (int i = 0; i < DES_IP_SIZE; i++)
    {
        uint64_t bit = (*block >> (64 - IP[i])) & 1;
        new_block |= bit << (64 - i - 1);
    }
    *block = new_block;
}

void des_pi(uint64_t *block)
{
    uint64_t new_block = 0;
    for (int i = 0; i < DES_PI_SIZE; i++)
    {
        uint64_t bit = (*block >> (64 - PI[i])) & 1;
        new_block |= bit << (64 - i - 1);
    }
    *block = new_block;
}

void des_fp(uint32_t *subblock)
{
    uint32_t new_subblock = 0;
    for (int i = 0; i < DES_P_SIZE; i++)
    {
        uint32_t bit = (*subblock >> (32 - P[i])) & 1;
        new_subblock |= bit << (32 - i - 1);
    }
    *subblock = new_subblock;
}

void des_fexpand(uint32_t *subblock, uint64_t *new_subblock)
{
    uint64_t new_block = 0;
    for (int i = 0; i < DES_E_SIZE; i++)
    {
        uint64_t bit = (*subblock >> (32 - E[i])) & 1;
        new_block |= bit << (48 - i - 1);
    }
    *new_subblock = new_block;
}

void des_feistel(uint64_t *block, des_ctx_t *ctx, des_mode_t mode)
{
    uint32_t l = *block >> 32;
    uint32_t r = *block & 0xFFFFFFFF;

    for (int i = 0; i < DES_ROUNDS; i++)
    {
        uint32_t tmp = r;

        if (mode == DES_ENCRYPT)
        {
            des_ffunc(&r, ctx->keys[i]);
        }
        else if (mode == DES_DECRYPT)
        {
            des_ffunc(&r, ctx->keys[DES_ROUNDS - i - 1]);
        }

        r = l ^ r;
        l = tmp;
    }

    *block = ((uint64_t)r << 32) | l;
}

void des_sbox(uint64_t *subblock, uint32_t *res_subblock)
{
    uint32_t new_subblock = 0;
    for (int i = 0; i < 8; i++)
    {
        uint8_t s_input = ((*subblock >> (48 - 6 * (i + 1))) & 0x3F);
        uint8_t row = ((s_input & 0x20) >> 4) | (s_input & 1);
        uint8_t col = (s_input >> 1) & 0xF;
        uint8_t s_output = DES_SBOX[i][row][col];
        new_subblock |= s_output << (32 - 4 * (i + 1));
    }
    *res_subblock = new_subblock;
}

void des_ffunc(uint32_t *subblock, const uint64_t subkey)
{
    uint64_t expanded_subblock;
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
        uint64_t bit = (key >> (64 - PC1[i])) & 1;
        pc1_key |= bit << (56 - i - 1);
    }

    // Split key into two 28-bit halves
    uint32_t c = pc1_key >> 28;
    uint32_t d = pc1_key & 0xFFFFFFF;

    for (int i = 0; i < DES_ROUNDS; i++)
    {
        c = ((c << SHIFTS[i]) | (c >> (28 - SHIFTS[i]))) & 0xFFFFFFF;
        d = ((d << SHIFTS[i]) | (d >> (28 - SHIFTS[i]))) & 0xFFFFFFF;

        uint64_t cd = ((uint64_t)c << 28) | d;
        uint64_t subkey = 0;
        for (int j = 0; j < 48; j++)
        {
            uint64_t bit = (cd >> (56 - PC2[j])) & 1;
            subkey |= bit << (48 - j - 1);
        }
        ctx->keys[i] = subkey;
    }
}

/*
 * DES encryption/decryption function
 * input: array of 64-bit blocks
 * output: array of 64-bit blocks
 * key: 64-bit key
 * len: number of blocks
 * mode: 'e' for encryption, 'd' for decryption
 */
void des(uint64_t *input, uint64_t *output, const uint64_t key, int len, des_mode_t mode)
{
    des_ctx_t ctx;
    des_key_schedule(key, &ctx);

    for (int i = 0; i < len; i++)
    {
        uint64_t block = input[i];

        des_ip(&block);

        des_feistel(&block, &ctx, mode);

        des_pi(&block);

        output[i] = block;
    }
}

void des_file(const char *input_file, const char *output_file, const uint64_t key, des_mode_t mode)
{
    FILE *input = fopen(input_file, "rb");
    FILE *output = fopen(output_file, "wb");

    if (input == NULL || output == NULL)
    {
        perror("Error opening file");
        exit(1);
    }

    fseek(input, 0, SEEK_END);
    size_t file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    uint64_t *input_blocks, *output_blocks;
    size_t len = 0;

    if (mode == DES_ENCRYPT)
    {
        unsigned char *input_data = malloc(file_size);
        fread(input_data, 1, file_size, input);
        unsigned char *padded_data = pkcs7_padding(input_data, file_size, DES_BLOCK_SIZE);
        len = strlen((const char *)padded_data) / 8;
        input_blocks = malloc(len * sizeof(uint64_t));
        memcpy(input_blocks, padded_data, len * 8);
    }
    else
    {
        if (file_size % 8 != 0)
        {
            perror("Invalid file size");
            exit(1);
        }
        len = file_size / 8;
        input_blocks = malloc(len * sizeof(uint64_t));
        fread(input_blocks, sizeof(uint64_t), len, input);
    }
    output_blocks = malloc(len * sizeof(uint64_t));

    des(input_blocks, output_blocks, key, len, mode);

    if (mode == DES_ENCRYPT)
    {
        fwrite(output_blocks, sizeof(uint64_t), len, output);
    }
    else
    {
        unsigned char *output_data = malloc(len * 8);
        memcpy(output_data, output_blocks, len * 8);
        unsigned char *unpadded_data = pkcs7_unpadding(output_data, len * 8, DES_BLOCK_SIZE);
        fwrite(unpadded_data, 1, strlen((const char *)unpadded_data), output);
    }

    fclose(input);
    fclose(output);

    free(input_blocks);
    free(output_blocks);
}