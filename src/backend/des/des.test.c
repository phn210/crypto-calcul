#include "des.h"
#include "conversion.h"

int compare_files(const char *file1, const char *file2)
{
    FILE *f1 = fopen(file1, "rb");
    FILE *f2 = fopen(file2, "rb");

    if (f1 == NULL || f2 == NULL)
    {
        if (f1)
            fclose(f1);
        if (f2)
            fclose(f2);
        return 0;
    }

    int result = 1;
    while (1)
    {
        unsigned char buffer1[1024];
        unsigned char buffer2[1024];

        size_t bytesRead1 = fread(buffer1, 1, sizeof(buffer1), f1);
        size_t bytesRead2 = fread(buffer2, 1, sizeof(buffer2), f2);

        if (bytesRead1 != bytesRead2 || memcmp(buffer1, buffer2, bytesRead1) != 0)
        {
            result = 0;
            break;
        }

        if (bytesRead1 == 0 || bytesRead2 == 0)
        {
            break;
        }
    }

    fclose(f1);
    fclose(f2);

    return result;
}

int main()
{
    printf("\n===================== DES TEST =====================\n\n");

    uint64_t key = 0x133457799BBCDFF1;
    char *message = "Hello world!\0";

    size_t len = strlen(message);

    // printf("Plaintext: %s\n", message);

    // Pad input if necessary
    size_t padded_len;
    unsigned char *padded_message = pkcs7_padding((unsigned char *)message, len, &padded_len, DES_BLOCK_SIZE);
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

    // printf("Plaintext (hex): ");
    // for (size_t i = 0; i < len_blocks; i++)
    // {
    //     printf("%016lx ", input_blocks[i]);
    // }

    // Encrypt message
    des(input_blocks, encrypted, key, len_blocks, DES_ENCRYPT);

    // printf("\nCiphertext (hex): ");
    // for (size_t i = 0; i < len_blocks; i++)
    // {
    //     printf("%016lx ", encrypted[i]);
    // }

    // Decrypt message
    des(encrypted, decrypted, key, len_blocks, DES_DECRYPT);

    // printf("\nDecrypted (hex): ");
    // for (size_t i = 0; i < len_blocks; i++)
    // {
    //     printf("%016lx ", decrypted[i]);
    // }

    // Convert decrypted blocks back to text
    unsigned char *decrypted_message = malloc(padded_len);
    for (size_t i = 0; i < len_blocks; i++)
    {
        for (size_t j = 0; j < 8; j++)
        {
            decrypted_message[i * 8 + j] = (decrypted[i] >> (64 - 8 * (j + 1))) & 0xFF;
        }
    }

    // Remove padding
    size_t decrypted_len;
    unsigned char *unpadded_message = pkcs7_unpadding(decrypted_message, padded_len, &decrypted_len, DES_BLOCK_SIZE);

    // printf("\nDecrypted: %s\n", decrypted_message);
    printf("DES:\t\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    // printf("\nFile encryption/decryption\n");

    char *input_file = "des_input_file.txt";
    char *encrypted_file = "des_output_encrypted_file.txt";
    char *decrypted_file = "des_output_decrypted_file.txt";

    des_file(input_file, encrypted_file, key, DES_ENCRYPT);

    // printf("File encrypted successfully to %s\n", encrypted_file);

    des_file(encrypted_file, decrypted_file, key, DES_DECRYPT);

    // printf("File decrypted successfully to %s\n", decrypted_file);

    int result = compare_files(input_file, decrypted_file);
    printf("DES File:\t%s\n", result ? "PASS" : "FAIL");

    free(encrypted);
    free(decrypted);
    free(input_blocks);
    free(decrypted_message);
    free(padded_message);
    free(unpadded_message);

    // printf("\n===================================================\n\n");

    return 0;
}
