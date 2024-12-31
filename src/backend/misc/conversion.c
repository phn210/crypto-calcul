#include "conversion.h"

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len, BYTE_ORDER order)
{
    mpz_import(result, len, order, 1, 0, 0, buf);
}

void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, BYTE_ORDER order)
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

size_t count_bytes(const mpz_t n)
{
    size_t bit_count = mpz_sizeinbase(n, 2);
    return (bit_count + 7) / 8;
}