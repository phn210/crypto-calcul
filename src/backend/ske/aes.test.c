#include "aes.h"

int main()
{
    printf("\n===================== AES TEST =====================\n\n");

    char *key = "133457799BBCDFF1133457799BBCDFF1";
    // char message[] = "Hello world!1234";
    char message[] = "Hello world! Myname is John Doe.";

    size_t len = strlen(message);
    size_t key_len = strlen(key);

    printf("Plaintext: %s\n", message);
    printf("Key: %s\n", key);
    printf("Plaintext (hex): ");
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", message[i]);
    }

    // Pad input if necessary
    // if (len % 8 != 0)
    // {
    //     des_padding(message, message, len);
    //     len += 8 - len % 8;
    // }

    size_t len_blocks = len / AES_BLOCK_SIZE;

    unsigned char key_hex[16];
    for (size_t i = 0; i < 16; i++) {
        sscanf(key + 2*i, "%2hhx", &key_hex[i]);
    }

    printf("\n--- AES ECB ---\n");

    unsigned char *encrypted_ecb = malloc(len);
    unsigned char *decrypted_ecb = malloc(len);
    
    // Convert text message to blocks in hex
    // unsigned char *input_blocks = malloc(len_blocks * AES_BLOCK_SIZE);
    // for (size_t i = 0; i < len_blocks; i++)
    // {
    //     for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
    //     {
    //         input_blocks[i * AES_BLOCK_SIZE + j] = message[i * AES_BLOCK_SIZE + j];
    //     }
    // }


    aes_encrypt_ecb(message, encrypted_ecb, key_hex, len, AES_KEY_SIZE_128);

    printf("\nEncrypted (ECB): ");
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", encrypted_ecb[i]);
    }

    aes_decrypt_ecb(encrypted_ecb, decrypted_ecb, key_hex, len, AES_KEY_SIZE_128);

    printf("\nDecrypted (ECB): %s\n", decrypted_ecb);



    printf("\n===================================================\n\n");

    free(encrypted_ecb);
    free(decrypted_ecb);

    return 0;
}

