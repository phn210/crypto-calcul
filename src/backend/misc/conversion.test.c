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

void test_invalid_hex_to_bigint()
{
    mpz_t result;
    const char *invalid_hex_str = "invalid_hex";

    // This should print an error message and exit
    hex_to_bigint(result, invalid_hex_str);
}

int main()
{
    printf("\n===================== CONVERSION TEST =====================\n\n");

    test_hex_to_bigint();
    test_bigint_to_hex();

    // Uncomment the following line to test invalid hex string handling
    // test_invalid_hex_to_bigint();

    return 0;
}