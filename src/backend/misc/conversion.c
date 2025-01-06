#include "conversion.h"

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len, byte_order_t order)
{
    mpz_import(result, len, order, 1, 0, 0, buf);
}

void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, byte_order_t order)
{
    if (buf == NULL)
    {
        printf("Error: Memory allocation failed.\n");
        exit(1);
    }
    mpz_export(buf, len, order, 1, 0, 0, num);
}

void hex_to_bigint(mpz_t result, const char *buf)
{
    mpz_init(result);
    if (buf == NULL || *buf == '\0')
    {
        printf("Error: Null or empty hex string.\n");
        exit(1);
    }
    if (mpz_set_str(result, buf, 16) != 0)
    {
        mpz_clear(result);
        printf("Error: Invalid hex string format.\n");
        exit(1);
    }
}

void bigint_to_hex(char **buf, const mpz_t num)
{
    *buf = mpz_get_str(NULL, 16, num);
    if (buf == NULL)
    {
        printf("Error: Conversion to hex string failed.\n");
        exit(1);
    }
}

void string_to_hex(unsigned char *output, const unsigned char *input, size_t input_len)
{
    for (size_t i = 0; i < input_len; i++)
    {
        snprintf((char *)(output + i * 2), 3, "%02x", input[i]);
    }
    output[input_len * 2] = '\0';
}

void hex_to_string(unsigned char *output, const unsigned char *input, size_t input_len)
{
    if (input_len % 2 != 0)
    {
        printf("Error: Hex string length must be even.\n");
        return;
    }

    for (size_t i = 0; i < input_len; i += 2)
    {
        unsigned int byte;
        sscanf((const char *)&input[i], "%2x", &byte);
        output[i / 2] = (unsigned char)byte;
    }
    output[input_len / 2] = '\0';
}

size_t count_bytes(const mpz_t n)
{
    size_t bit_count = mpz_sizeinbase(n, 2);
    return (bit_count + 7) / 8;
}

unsigned char *pkcs7_padding(unsigned char *input, size_t len, size_t block_size)
{
    size_t padded_len = len + (block_size - len % block_size);
    size_t padding_value = block_size - (len % block_size);
    unsigned char *output = malloc(padded_len);
    if (output == NULL)
    {
        printf("Error: Memory allocation failed.\n");
        exit(1);
    }
    memcpy(output, input, len);
    for (size_t i = len; i < padded_len; i++)
    {
        output[i] = padding_value;
    }
    output[padded_len] = '\0';
    return output;
}

unsigned char *pkcs7_unpadding(unsigned char *input, size_t len, size_t block_size)
{
    if (len % block_size != 0)
    {
        printf("Error: Invalid input length for PKCS#7 unpadding.\n");
        exit(1);
    }
    size_t padding_value = input[len - 1];
    if (padding_value > block_size)
    {
        printf("Error: Invalid padding value.\n");
        exit(1);
    }
    for (size_t i = len - padding_value; i < len; i++)
    {
        if (input[i] != padding_value)
        {
            printf("Error: Invalid padding value.\n");
            exit(1);
        }
    }
    unsigned char *output = malloc(len - padding_value);
    if (output == NULL)
    {
        printf("Error: Memory allocation failed.\n");
        exit(1);
    }
    memcpy(output, input, len - padding_value);
    return output;
}