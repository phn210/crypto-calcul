#include "hmac.h"
#include "sha3.h"

void test_hmac_function()
{
    const char *key = "secret";
    const char *data = "Hello, HMAC!";
    unsigned char mac[64]; // Maximum length for SHA3-512

    hmac((void *)key, strlen(key), (void *)data, strlen(data), mac, L1, SHA3);

    // printf("HMAC: ");
    // for (int i = 0; i < 32; i++) // SHA3-256 output length
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int result = hmac_verify((void *)key, strlen(key), (void *)data, strlen(data), mac, L1, SHA3);
    printf("HMAC:\t\t%s\n", result == 0 ? "PASSED" : "FAILED");
}

void test_hmac_file_function()
{
    const char *key = "secret";
    const char *filename = "mac_input_file.txt";
    unsigned char mac[64]; // Maximum length for SHA3-512

    hmac_file(filename, (void *)key, strlen(key), mac, L1, SHA2);

    // printf("HMAC File: ");
    // for (int i = 0; i < 32; i++) // SHA3-256 output length
    // {
    //     printf("%02x", mac[i]);
    // }
    // printf("\n");

    int result = hmac_file_verify(filename, (void *)key, strlen(key), mac, L1, SHA2);
    printf("HMAC File:\t%s\n", result == 0 ? "PASSED" : "FAILED");
}

int main()
{
    printf("\n===================== HMAC TEST =====================\n\n");

    test_hmac_function();
    test_hmac_file_function();

    return 0;
}