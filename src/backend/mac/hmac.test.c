#include "hmac.h"
#include "sha3.h"

void test_hmac_function()
{
    const char *key = "secret";
    const char *data = "Hello, HMAC!";
    unsigned char mac[64]; // Maximum length for SHA3-512

    hmac((void *)key, strlen(key), (void *)data, strlen(data), mac, L1, SHA3);
    
    printf("HMAC: ");
    for (int i = 0; i < 32; i++) // SHA3-256 output length
    {
        printf("%02x", mac[i]);
    }
    printf("\n");
}

int main()
{
    printf("\n===================== HMAC TEST =====================\n\n");

    // test_hmac_sha3();
    test_hmac_function();

    return 0;
}