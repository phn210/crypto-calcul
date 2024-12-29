#include "conversion.h"

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len)
{
    mpz_import(result, len, 1, 1, 0, 0, buf);
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