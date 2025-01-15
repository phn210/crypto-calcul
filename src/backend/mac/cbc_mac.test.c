#include "cbc_mac.h"

void test_cbc_mac_function()
{
    const char *key = "secret";
    const char *data = "Hello, CBC-MAC!";
    unsigned char mac[AES_BLOCK_SIZE];

    cbc_mac((void *)key, strlen(key), (void *)data, strlen(data), mac, L1);

    // printf("CBC-MAC: ");
    // for (int i = 0; i < 16; i++) // AES block size
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int result = cbc_mac_verify((void *)key, strlen(key), (void *)data, strlen(data), mac, L1);
    printf("CBC-MAC:\t%s\n", result == 0 ? "PASSED" : "FAILED");
}

void test_cbc_mac_file_function()
{
    const char *key = "secret";
    const char *filename = "mac_input_file.txt";
    unsigned char mac[AES_BLOCK_SIZE];

    cbc_mac_file(filename, (void *)key, strlen(key), mac, L1);

    // printf("CBC-MAC File: ");
    // for (int i = 0; i < AES_BLOCK_SIZE; i++) // AES block size
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int result = cbc_mac_file_verify(filename, (void *)key, strlen(key), mac, L1);
    printf("CBC-MAC File:\t%s\n", result == 0 ? "PASSED" : "FAILED");
}

int main()
{
    printf("\n===================== CBC-MAC TEST =====================\n\n");

    test_cbc_mac_function();
    test_cbc_mac_file_function();

    return 0;
}