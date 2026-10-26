#include "cbc_mac.h"
#include "test_util.h"

void test_cbc_mac_function()
{
    const char *key = "secret";
    const char *data = "Hello, CBC-MAC!";
    unsigned char mac[AES_BLOCK_SIZE];

    EXPECT_OK(cbc_mac((void *)key, strlen(key), (void *)data, strlen(data), mac, L1));

    // printf("CBC-MAC: ");
    // for (int i = 0; i < 16; i++) // AES block size
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int passed = cbc_mac_verify((void *)key, strlen(key), (void *)data, strlen(data), mac, AES_BLOCK_SIZE, L1) == CC_OK;

    // Tampered data, wrong MAC length and unsupported level are rejected
    passed &= cbc_mac_verify((void *)key, strlen(key), (void *)"Hello, CBC-MAC?", strlen(data), mac, AES_BLOCK_SIZE, L1) == CC_ERR_VERIFY;
    passed &= cbc_mac_verify((void *)key, strlen(key), (void *)data, strlen(data), mac, 8, L1) == CC_ERR_VERIFY;
    passed &= cbc_mac((void *)key, strlen(key), (void *)data, strlen(data), mac, L0) == CC_ERR_INVALID_ARG;

    // 256-bit keys use the whole key (bytes past the 16th used to be read out of bounds)
    unsigned char mac_a[AES_BLOCK_SIZE], mac_b[AES_BLOCK_SIZE];
    const char *key_a = "0123456789abcdef0123456789abcdeA";
    const char *key_b = "0123456789abcdef0123456789abcdeB";
    passed &= cbc_mac((void *)key_a, 32, (void *)data, strlen(data), mac_a, L3) == CC_OK &&
              cbc_mac((void *)key_b, 32, (void *)data, strlen(data), mac_b, L3) == CC_OK &&
              memcmp(mac_a, mac_b, AES_BLOCK_SIZE) != 0;
    printf("CBC-MAC:\t%s\n", passed ? "PASSED" : "FAILED");
}

void test_cbc_mac_file_function()
{
    const char *key = "secret";
    const char *filename = "mac_input_file.txt";
    unsigned char mac[AES_BLOCK_SIZE];

    EXPECT_OK(cbc_mac_file(filename, (void *)key, strlen(key), mac, L1));

    // printf("CBC-MAC File: ");
    // for (int i = 0; i < AES_BLOCK_SIZE; i++) // AES block size
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int result = cbc_mac_file_verify(filename, (void *)key, strlen(key), mac, AES_BLOCK_SIZE, L1) == CC_OK;
    printf("CBC-MAC File:\t%s\n", result ? "PASSED" : "FAILED");
}

int main()
{
    printf("\n===================== CBC-MAC TEST =====================\n\n");

    test_cbc_mac_function();
    test_cbc_mac_file_function();

    return 0;
}