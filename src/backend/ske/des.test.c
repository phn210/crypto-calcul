#include "des.h"

int main()
{
    printf("\n===================== DES TEST =====================\n\n");

    uint64_t key = 0x133457799BBCDFF1;
    char message[] = "Hello world!";

    size_t len = strlen(message);

    printf("Plaintext: %s\n", message);

    // Pad input if necessary
    if (len % DES_BLOCK_SIZE != 0)
    {
        des_padding(message, message, len);
        len += DES_BLOCK_SIZE - len % DES_BLOCK_SIZE;
    }

    size_t len_blocks = len / DES_BLOCK_SIZE;

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

    printf("Plaintext (hex): ");
    for (size_t i = 0; i < len_blocks; i++)
    {
        printf("%016lx ", input_blocks[i]);
    }

    // Encrypt message
    des(input_blocks, encrypted, key, len_blocks, 'e');

    printf("\nCiphertext (hex): ");
    for (size_t i = 0; i < len_blocks; i++)
    {
        printf("%016lx ", encrypted[i]);
    }

    printf("\n---\n");

    // Decrypt message
    des(encrypted, decrypted, key, len_blocks, 'd');

    printf("Decrypted (hex): ");
    for (size_t i = 0; i < len_blocks; i++)
    {
        printf("%016lx ", decrypted[i]);
    }

    // Remove padding if necessary
    size_t padding_len = decrypted[len - 1];
    if (padding_len > 0 && padding_len <= 8)
    {
        len -= padding_len;
        decrypted[len] = '\0';
    }

    // Convert decrypted blocks back to text
    char *decrypted_message = malloc(len + 1);
    for (size_t i = 0; i < len_blocks; i++)
    {
        for (size_t j = 0; j < 8; j++)
        {
            decrypted_message[i * 8 + j] = (decrypted[i] >> (64 - 8 * (j + 1))) & 0xFF;
        }
    }
    decrypted_message[len] = '\0';

    printf("\nDecrypted message: %s\n", decrypted_message);


    free(encrypted);
    free(decrypted);
    free(input_blocks);
    free(decrypted_message);

    printf("\n===================================================\n\n");

    return 0;
}

