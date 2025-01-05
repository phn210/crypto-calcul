#include "cbc_mac.h"

void test_cbc_mac_function()
{
    const unsigned char *key = "secret";
    const unsigned char *data = "Hello, CBC-MAC!";
    unsigned char *mac = malloc(AES_BLOCK_SIZE);

    cbc_mac((void *)key, strlen(key), (void *)data, strlen(data), mac, L1);

    printf("CBC-MAC: ");
    for (int i = 0; i < 16; i++) // AES block size
    {
        printf("%02x", mac[i]);
    }
    printf("\n");
}

int main()
{
    printf("\n===================== CBC-MAC TEST =====================\n\n");

    test_cbc_mac_function();

    return 0;
}