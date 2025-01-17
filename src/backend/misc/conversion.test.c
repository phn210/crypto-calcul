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
    unsigned char *bytes = malloc(count_bytes(num));
    if (bytes == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    bigint_to_bytes(bytes, &len, num, BIG);
    // gmp_printf("BigInt to Bytes: %Zd -> ", num);
    // for (size_t i = 0; i < len; i++)
    // {
    //     printf("%02x", bytes[i]);
    // }
    // printf("\n");

    bytes_to_bigint(result, bytes, len, BIG);

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

    mpz_clears(num, result, NULL);
    free(bytes);
}

void test_string_and_hex()
{
    char *input = "Hello, world!\0";
    size_t len = strlen(input);
    unsigned char *hex = malloc(len * 2 + 1);
    char *output = malloc(len + 1);
    if (hex == NULL || output == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    string_to_hex(hex, input, len);
    // printf("String to Hex: %s -> %s\n", input, hex);
    hex_to_string(output, hex, len * 2);
    // printf("Hex to String: %s -> %s\n", hex, output);

    printf("String <-> Hex:\t\t");
    if (memcmp(input, output, len) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    free(hex);
    free(output);
}

void test_pkcs7_padding()
{
    char *input = "Hello, world!\0";
    size_t len = strlen(input);
    size_t block_size = 8;
    size_t padded_len, unpadded_len;

    unsigned char *padded = pkcs7_padding((unsigned char *)input, len, &padded_len, block_size);
    unsigned char *unpadded = pkcs7_unpadding(padded, padded_len, &unpadded_len, block_size);

    printf("PKCS#7 Padding:\t\t%s\n", memcmp(input, unpadded, unpadded_len) == 0 ? "PASSED" : "FAILED");
    free(padded);
    free(unpadded);
}

int main()
{
    printf("\n===================== CONVERSION TEST =====================\n\n");

    test_bigint_and_hex();
    test_bigint_and_bytes();
    test_string_and_hex();
    test_pkcs7_padding();

    return 0;
}