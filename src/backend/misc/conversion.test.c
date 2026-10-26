#include "conversion.h"
void test_bigint_and_hex()
{
    mpz_t num, result;
    mpz_init_set_str(num, "1a2b3c4d5e6f", 16);
    mpz_init(result);

    char *buf;
    cc_status_t status = bigint_to_hex(&buf, num);
    if (status == CC_OK)
        status = hex_to_bigint(result, buf);

    printf("mpz_t <-> Hex:\t\t");
    if (status == CC_OK && mpz_cmp(num, result) == 0 && hex_to_bigint(result, "xyz") == CC_ERR_INVALID_INPUT)
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
    cc_status_t status = hex_to_string(output, hex, len * 2);

    printf("String <-> Hex:\t\t");
    if (status == CC_OK && memcmp(input, output, len) == 0 && hex_to_string(output, hex, 3) == CC_ERR_INVALID_INPUT)
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

    unsigned char *padded = NULL, *unpadded = NULL;

    int passed = pkcs7_padding((unsigned char *)input, len, &padded, &padded_len, block_size) == CC_OK &&
                 pkcs7_unpadding(padded, padded_len, &unpadded, &unpadded_len, block_size) == CC_OK &&
                 unpadded_len == len && memcmp(input, unpadded, unpadded_len) == 0;

    printf("PKCS#7 Padding:\t\t%s\n", passed ? "PASSED" : "FAILED");
    free(padded);
    free(unpadded);
}

void test_pkcs7_invalid_padding()
{
    // Last byte claims 3 bytes of padding but the preceding bytes disagree
    unsigned char bad[8] = {'a', 'b', 'c', 'd', 'e', 0x01, 0x02, 0x03};
    unsigned char zero[8] = {0};
    unsigned char *out = NULL;
    size_t out_len;

    int passed = pkcs7_unpadding(bad, sizeof(bad), &out, &out_len, 8) == CC_ERR_DECRYPT &&
                 pkcs7_unpadding(zero, sizeof(zero), &out, &out_len, 8) == CC_ERR_DECRYPT &&
                 pkcs7_unpadding(bad, 7, &out, &out_len, 8) == CC_ERR_INVALID_INPUT &&
                 out == NULL;

    printf("PKCS#7 Invalid Padding:\t%s\n", passed ? "PASSED" : "FAILED");
}

void test_bigint_to_bytes_fixed()
{
    mpz_t num, result;
    mpz_init_set_str(num, "00ff", 16);
    mpz_init(result);

    unsigned char buf[4];
    int passed = bigint_to_bytes_fixed(buf, sizeof(buf), num) == CC_OK &&
                 buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0xff &&
                 bigint_to_bytes_fixed(buf, 0, num) == CC_ERR_INVALID_INPUT;

    mpz_set_ui(num, 0);
    passed = passed && bigint_to_bytes_fixed(buf, sizeof(buf), num) == CC_OK && buf[3] == 0;

    printf("mpz_t -> Fixed Bytes:\t%s\n", passed ? "PASSED" : "FAILED");
    mpz_clears(num, result, NULL);
}

int main()
{
    printf("\n===================== CONVERSION TEST =====================\n\n");

    test_bigint_and_hex();
    test_bigint_and_bytes();
    test_string_and_hex();
    test_pkcs7_padding();
    test_pkcs7_invalid_padding();
    test_bigint_to_bytes_fixed();

    return 0;
}