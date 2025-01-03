#include "conversion.h"
void test_bigint_and_hex()
{
    mpz_t num, result;
    mpz_init_set_str(num, "1a2b3c4d5e6f", 16);
    mpz_init(result);

    char *buf;
    bigint_to_hex(&buf, num);
    // gmp_printf("BigInt to Hex: %Zd -> %s\n", num, buf);

    hex_to_bigint(result, buf);
    // gmp_printf("Hex to BigInt: %s -> %Zd\n", buf, result);

    printf("mpz_t <-> Hex:\t\t");
    if (mpz_cmp(num, result) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(num, result, NULL);
    free(buf);
}

void test_bigint_and_bytes()
{
    mpz_t num, result;
    mpz_init_set_str(num, "1a2b3c4d5e6f", 16);
    mpz_init(result);

    size_t len;
    unsigned char *bytes = (unsigned char *)malloc(count_bytes(num));

    bigint_to_bytes(bytes, &len, num, BIG_ENDIAN);
    // gmp_printf("BigInt to Bytes: %Zd -> ", num);
    // for (size_t i = 0; i < len; i++)
    // {
    //     printf("%02x", bytes[i]);
    // }
    // printf("\n");

    bytes_to_bigint(result, bytes, len, BIG_ENDIAN);

    // gmp_printf("Bytes to BigInt: ");
    // for (size_t i = 0; i < len; i++)
    // {
    //     printf("%02x", bytes[i]);
    // }
    // gmp_printf(" -> %Zd\n", result);

    printf("mpz_t <-> Bytes:\t");
    if (mpz_cmp(num, result) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clear(num);
    free(bytes);
}

int main()
{
    printf("\n===================== CONVERSION TEST =====================\n\n");

    test_bigint_and_hex();
    test_bigint_and_bytes();

    // Uncomment the following line to test invalid hex string handling
    // test_invalid_hex_to_bigint();

    return 0;
}