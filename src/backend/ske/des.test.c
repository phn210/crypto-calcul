#include "des.h"

int main()
{
    printf("\n===================== DES TEST =====================\n\n");

    uint64_t key = 0x133457799BBCDFF1;
    char message[] = "Hello, World!";
    size_t len = strlen(message);
    char *encrypted = malloc(len);
    char *decrypted = malloc(len);

    des(message, encrypted, key, len);
    printf("Encrypted: %s\n", encrypted);

    des(encrypted, decrypted, key, len);
    printf("Decrypted: %s\n", decrypted);

    free(encrypted);
    free(decrypted);

    printf("\n===================================================\n\n");

    return 0;
}

