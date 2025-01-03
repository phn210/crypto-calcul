#include "des.h"
#include "conversion.h"

int main()
{
    printf("\n===================== DES TEST =====================\n\n");

    uint64_t key = 0x133457799BBCDFF1;
    unsigned char message[] = "Hello world!";

    size_t len = strlen(message);

    printf("Plaintext: %s\n", message);

    // Pad input if necessary
    char *padded_message = pkcs7_padding(message, len, DES_BLOCK_SIZE);

    size_t padded_len = strlen(padded_message);
    size_t len_blocks = padded_len / DES_BLOCK_SIZE;

    uint64_t *encrypted = malloc(len_blocks * sizeof(uint64_t));
    uint64_t *decrypted = malloc(len_blocks * sizeof(uint64_t));

    // Convert text message to blocks in hex
    uint64_t *input_blocks = malloc(len_blocks * sizeof(uint64_t));
    for (size_t i = 0; i < len_blocks; i++)
    {
        input_blocks[i] = 0;
        for (size_t j = 0; j < 8; j++)
        {
            input_blocks[i] |= (uint64_t)padded_message[i * 8 + j] << (64 - 8 * (j + 1));
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

    // Convert decrypted blocks to text
    char *decrypted_message = malloc(padded_len);
    for (size_t i = 0; i < len_blocks; i++)
    {
        for (size_t j = 0; j < 8; j++)
        {
            decrypted_message[i * 8 + j] = (decrypted[i] >> (64 - 8 * (j + 1))) & 0xFF;
        }
    }

    // Remove padding
    decrypted_message = pkcs7_unpadding(decrypted_message, padded_len * DES_BLOCK_SIZE, DES_BLOCK_SIZE);

    printf("\nDecrypted: %s\n", decrypted_message);


    free(encrypted);
    free(decrypted);
    free(input_blocks);
    free(decrypted_message);

    printf("\n===================================================\n\n");

    return 0;
}

