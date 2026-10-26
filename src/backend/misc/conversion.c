#include "conversion.h"

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len, byte_order_t order)
{
    mpz_import(result, len, order, 1, 0, 0, buf);
}

void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, byte_order_t order)
{
    mpz_export(buf, len, order, 1, 0, 0, num);
}

cc_status_t bigint_to_bytes_fixed(unsigned char *buf, size_t len, const mpz_t num)
{
    if (mpz_sgn(num) < 0)
        return CC_ERR_INVALID_INPUT;

    size_t num_len = mpz_sgn(num) == 0 ? 0 : count_bytes(num);
    if (num_len > len)
        return CC_ERR_INVALID_INPUT;

    memset(buf, 0, len - num_len);
    size_t written = 0;
    mpz_export(buf + len - num_len, &written, 1, 1, 0, 0, num);
    return CC_OK;
}

cc_status_t hex_to_bigint(mpz_t result, const char *buf)
{
    if (buf == NULL || *buf == '\0')
        return CC_ERR_INVALID_INPUT;
    if (mpz_set_str(result, buf, 16) != 0)
        return CC_ERR_INVALID_INPUT;
    return CC_OK;
}

cc_status_t bigint_to_hex(char **buf, const mpz_t num)
{
    *buf = mpz_get_str(NULL, 16, num);
    if (*buf == NULL)
        return CC_ERR_NOMEM;
    return CC_OK;
}

void string_to_hex(unsigned char *output, const char *input, size_t input_len)
{
    for (size_t i = 0; i < input_len; i++)
    {
        snprintf((char *)(output + i * 2), 3, "%02x", (unsigned char)input[i]);
    }
    output[input_len * 2] = '\0';
}

cc_status_t hex_to_string(char *output, const unsigned char *input, size_t input_len)
{
    if (input_len % 2 != 0)
        return CC_ERR_INVALID_INPUT;

    for (size_t i = 0; i < input_len; i += 2)
    {
        unsigned int byte;
        if (sscanf((const char *)&input[i], "%2x", &byte) != 1)
            return CC_ERR_INVALID_INPUT;
        output[i / 2] = (char)byte;
    }
    output[input_len / 2] = '\0';
    return CC_OK;
}

size_t count_bytes(const mpz_t n)
{
    size_t bit_count = mpz_sizeinbase(n, 2);
    return (bit_count + 7) / 8;
}

cc_status_t pkcs7_padding(const unsigned char *input, size_t len, unsigned char **output, size_t *out_len, size_t block_size)
{
    if (block_size == 0 || block_size > 255)
        return CC_ERR_INVALID_ARG;

    size_t padding_value = block_size - (len % block_size);
    size_t padded_len = len + padding_value;
    unsigned char *padded = malloc(padded_len + 1);
    if (padded == NULL)
        return CC_ERR_NOMEM;

    memcpy(padded, input, len);
    memset(padded + len, (int)padding_value, padding_value);
    padded[padded_len] = '\0';

    *output = padded;
    *out_len = padded_len;
    return CC_OK;
}

cc_status_t pkcs7_unpadding(const unsigned char *input, size_t len, unsigned char **output, size_t *out_len, size_t block_size)
{
    if (block_size == 0 || block_size > 255)
        return CC_ERR_INVALID_ARG;
    if (len == 0 || len % block_size != 0)
        return CC_ERR_INVALID_INPUT;

    // A wrong key or corrupted ciphertext shows up as invalid padding
    size_t padding_value = input[len - 1];
    if (padding_value == 0 || padding_value > block_size)
        return CC_ERR_DECRYPT;
    for (size_t i = len - padding_value; i < len; i++)
    {
        if (input[i] != padding_value)
            return CC_ERR_DECRYPT;
    }

    size_t unpadded_len = len - padding_value;
    unsigned char *unpadded = malloc(unpadded_len + 1);
    if (unpadded == NULL)
        return CC_ERR_NOMEM;

    memcpy(unpadded, input, unpadded_len);
    unpadded[unpadded_len] = '\0';

    *output = unpadded;
    *out_len = unpadded_len;
    return CC_OK;
}
