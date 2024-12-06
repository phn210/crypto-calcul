#include "des.c"

int main()
{
    printf("\n===================== DES TEST =====================\n\n");

    uint64_t key = 0x133457799BBCDFF1;
    char message[] = "Hello world!";

    size_t len = strlen(message);

    // Pad input if necessary
    if (len % 8 != 0)
    {
        des_padding(message, message, len);
        len += 8 - len % 8;
    }

    size_t len_blocks = len / 8;

    uint64_t *encrypted = malloc(len_blocks * sizeof(uint64_t));
    uint64_t *decrypted = malloc(len_blocks * sizeof(uint64_t));

    // Convert text message to blocks in hex
    uint64_t *input_blocks = malloc(len_blocks * sizeof(uint64_t));
    for (size_t i = 0; i < len_blocks; i++)
    {
        input_blocks[i] = 0;
        for (size_t j = 0; j < 8; j++)
        {
            input_blocks[i] |= (uint64_t)message[i * 8 + j] << (64 - 8 * (j + 1));
        }
    }

    printf("Plaintext (with padding): %s\n", message);

    des(message, encrypted, key, len_blocks, 'e');

    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < len_blocks; i++)
    {
        printf("%016lx ", encrypted[i]);
    }

    printf("\n---\n");

    des(encrypted, decrypted, key, len_blocks, 'd');
    printf("Decrypted (hex): ");
    for (size_t i = 0; i < len_blocks; i++)
    {
        printf("%016lx ", decrypted[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    free(encrypted);
    free(decrypted);
    free(input_blocks);

    printf("\n===================================================\n\n");

    return 0;
}

