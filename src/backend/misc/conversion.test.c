#include "conversion.h"

void test_hex_to_bigint()
{
    mpz_t result;
    const char *buf = "1a2b3c4d5e6f";
    hex_to_bigint(result, buf);

    gmp_printf("Hex to BigInt: %s -> %Zd\n", buf, result);

    mpz_clear(result);
}

void test_bigint_to_hex()
{
    mpz_t num;
    mpz_init_set_str(num, "1a2b3c4d5e6f", 16);

    char *buf;
    bigint_to_hex(&buf, num);

    gmp_printf("BigInt to Hex: %Zd -> %s\n", num, buf);

    mpz_clear(num);
    free(buf);
}

void test_bytes_to_bigint()
{
    mpz_t result;
    const unsigned char bytes[] = {0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f};
    size_t len = sizeof(bytes) / sizeof(bytes[0]);

    mpz_init(result);
    bytes_to_bigint(result, bytes, len, BIG_ENDIAN);

    gmp_printf("Bytes to BigInt: ");
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", bytes[i]);
    }
    gmp_printf(" -> %Zd\n", result);

    mpz_clear(result);
}

void test_bigint_to_bytes()
{
    mpz_t num;
    mpz_init_set_str(num, "1a2b3c4d5e6f", 16);

    size_t len;
    unsigned char *bytes = (unsigned char *)malloc(count_bytes(num));

    bigint_to_bytes(bytes, &len, num, BIG_ENDIAN);

    gmp_printf("BigInt to Bytes: %Zd -> ", num);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", bytes[i]);
    }
    printf("\n");

    mpz_clear(num);
    free(bytes);
}

int main()
{
    printf("\n===================== CONVERSION TEST =====================\n\n");

    test_hex_to_bigint();
    test_bigint_to_hex();
    test_bytes_to_bigint();
    test_bigint_to_bytes();

    // Uncomment the following line to test invalid hex string handling
    // test_invalid_hex_to_bigint();

    return 0;
}