#include "aes.h"
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
    printf("\n===================== AES TEST =====================\n\n");

    char *key = "133457799BBCDFF1133457799BBCDFF1";
    char message[] = "Hello world! My name is John Doe.\0";

    size_t len = strlen((const char *)message);
    // size_t key_len = strlen((const char *)key);

    // printf("Plaintext: %s\n", message);
    // printf("Key: %s\n", key);
    // printf("Plaintext hex: ");
    // for (size_t i = 0; i < len; i++)
    // {
    //     printf("%02x", message[i]);
    // }

    // Pad input if necessary
    size_t padded_len;
    unsigned char *padded_message = pkcs7_padding((unsigned char *)message, len, &padded_len, AES_BLOCK_SIZE);
    // size_t len_blocks = padded_len / AES_BLOCK_SIZE;

    // printf("\nPadded message hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", padded_message[i]);
    // }

    // Convert key to hex
    unsigned char key_hex[AES_KEY_SIZE_128];
    for (size_t i = 0; i < AES_KEY_SIZE_128; i++)
    {
        sscanf(key + 2 * i, "%2hhx", &key_hex[i]);
    }

    // printf("\n\n--- AES ECB 128 bits ---\n");

    unsigned char *input_blocks = malloc(padded_len);
    if (input_blocks == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char *encrypted_ecb = malloc(padded_len);
    if (encrypted_ecb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_ecb = malloc(padded_len);
    if (decrypted_ecb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    aes_encrypt_ecb(input_blocks, encrypted_ecb, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nEncrypted (ECB): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_ecb[i]);
    // }

    aes_decrypt_ecb(encrypted_ecb, decrypted_ecb, key_hex, padded_len, AES_KEY_SIZE_128);

    // Unpad decrypted message
    size_t decrypted_len;
    unsigned char *unpadded_message = pkcs7_unpadding(decrypted_ecb, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (ECB): %s\n", unpadded_message);

    printf("AES-ECB-128:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_ecb);
    free(decrypted_ecb);
    free(unpadded_message);

    // printf("\n--- AES CBC 128 bits ---\n");

    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char iv_cbc[AES_BLOCK_SIZE] = {10};
    // printf("\nIV: ");
    // for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    // {
    //     printf("%02x", iv_cbc[i]);
    // }

    unsigned char *encrypted_cbc = malloc(padded_len);
    if (encrypted_cbc == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_cbc = malloc(padded_len);
    if (decrypted_cbc == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    aes_encrypt_cbc(input_blocks, encrypted_cbc, iv_cbc, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nEncrypted (CBC): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_cbc[i]);
    // }

    aes_decrypt_cbc(encrypted_cbc, decrypted_cbc, iv_cbc, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nDecrypted (CBC) hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", decrypted_cbc[i]);
    // }

    // Unpad decrypted message
    unpadded_message = pkcs7_unpadding(decrypted_cbc, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (CBC): %s\n", unpadded_message);

    printf("AES-CBC-128:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_cbc);
    free(decrypted_cbc);
    free(unpadded_message);

    // printf("\n--- AES CBC 256 bits ---\n");

    char *key_256 = "133457799BBCDFF1133457799BBCDFF1133457799BBCDFF1133457799BBCDFF1";
    unsigned char key_hex_256[AES_KEY_SIZE_256];

    for (size_t i = 0; i < AES_KEY_SIZE_256; i++)
    {
        sscanf(key_256 + 2 * i, "%2hhx", &key_hex_256[i]);
    }

    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char iv_cbc_256[AES_BLOCK_SIZE] = {0};
    // printf("\nIV: ");
    // for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    // {
    //     printf("%02x", iv_cbc_256[i]);
    // }

    unsigned char *encrypted_cbc_256 = malloc(padded_len);
    if (encrypted_cbc_256 == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_cbc_256 = malloc(padded_len);
    if (decrypted_cbc_256 == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    aes_encrypt_cbc(input_blocks, encrypted_cbc_256, iv_cbc_256, key_hex_256, padded_len, AES_KEY_SIZE_256);

    // printf("\nEncrypted (CBC): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_cbc_256[i]);
    // }

    aes_decrypt_cbc(encrypted_cbc_256, decrypted_cbc_256, iv_cbc_256, key_hex_256, padded_len, AES_KEY_SIZE_256);

    // printf("\nDecrypted (CBC) hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", decrypted_cbc_256[i]);
    // }

    // Unpad decrypted message
    unpadded_message = pkcs7_unpadding(decrypted_cbc_256, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (CBC): %s\n", unpadded_message);
    printf("AES-CBC-256:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_cbc_256);
    free(decrypted_cbc_256);
    free(unpadded_message);

    // printf("\n--- AES CFB 128 bits ---\n");

    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char iv_cfb[AES_BLOCK_SIZE] = {0};
    // printf("\nIV: ");
    // for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    // {
    //     printf("%02x", iv_cfb[i]);
    // }

    unsigned char *encrypted_cfb = malloc(padded_len);
    if (encrypted_cfb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_cfb = malloc(padded_len);
    if (decrypted_cfb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    aes_encrypt_cfb(input_blocks, encrypted_cfb, iv_cfb, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nEncrypted (CFB): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_cfb[i]);
    // }

    aes_decrypt_cfb(encrypted_cfb, decrypted_cfb, iv_cfb, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nDecrypted (CFB) hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", decrypted_cfb[i]);
    // }

    // Unpad decrypted message
    unpadded_message = pkcs7_unpadding(decrypted_cfb, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (CFB): %s\n", unpadded_message);
    printf("AES-CFB-128:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_cfb);
    free(decrypted_cfb);
    free(unpadded_message);

    // printf("\n--- AES OFB 128 bits ---\n");

    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char iv_ofb[AES_BLOCK_SIZE] = {0};
    // printf("\nIV: ");
    // for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    // {
    //     printf("%02x", iv_ofb[i]);
    // }

    unsigned char *encrypted_ofb = malloc(padded_len);
    if (encrypted_ofb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_ofb = malloc(padded_len);
    if (decrypted_ofb == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    aes_encrypt_ofb(input_blocks, encrypted_ofb, iv_ofb, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nEncrypted (OFB): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_ofb[i]);
    // }

    aes_decrypt_ofb(encrypted_ofb, decrypted_ofb, iv_ofb, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nDecrypted (OFB) hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", decrypted_ofb[i]);
    // }

    // Unpad decrypted message
    unpadded_message = pkcs7_unpadding(decrypted_ofb, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (OFB): %s\n", unpadded_message);
    printf("AES-OFB-128:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_ofb);
    free(decrypted_ofb);
    free(unpadded_message);

    // printf("\n--- AES CTR 128 bits ---\n");

    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char nonce_ctr[AES_BLOCK_SIZE] = {0};
    // printf("\nNonce: ");
    // for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    // {
    //     printf("%02x", nonce_ctr[i]);
    // }

    unsigned char *encrypted_ctr = malloc(padded_len);
    if (encrypted_ctr == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *decrypted_ctr = malloc(padded_len);

    if (decrypted_ctr == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    aes_ctr(input_blocks, encrypted_ctr, nonce_ctr, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nEncrypted (CTR): ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", encrypted_ctr[i]);
    // }

    aes_ctr(encrypted_ctr, decrypted_ctr, nonce_ctr, key_hex, padded_len, AES_KEY_SIZE_128);

    // printf("\nDecrypted (CTR) hex: ");
    // for (size_t i = 0; i < padded_len; i++)
    // {
    //     printf("%02x", decrypted_ctr[i]);
    // }

    // Unpad decrypted message
    unpadded_message = pkcs7_unpadding(decrypted_ctr, padded_len, &decrypted_len, AES_BLOCK_SIZE);

    // printf("\nDecrypted (CTR): %s\n", unpadded_message);
    printf("AES-CTR-128:\t%s\n", memcmp(message, unpadded_message, strlen(message)) == 0 ? "PASS" : "FAIL");

    free(encrypted_ctr);
    free(decrypted_ctr);
    free(unpadded_message);
    free(padded_message);

    // printf("\n--- AES File Encryption ---\n");

    char *input_file = "aes_input_file.txt";
    char *encrypted_file = "aes_output_encrypted_file.txt";
    char *decrypted_file = "aes_output_decrypted_file.txt";

    unsigned char iv_file[AES_BLOCK_SIZE] = {10};

    aes_file_encrypt(input_file, encrypted_file, key_hex, iv_file, AES_KEY_SIZE_128, AES_MODE_CBC);

    // printf("\nFile encrypted successfully to %s\n", encrypted_file);

    aes_file_decrypt(encrypted_file, decrypted_file, key_hex, iv_file, AES_KEY_SIZE_128, AES_MODE_CBC);

    int file_compare_result = compare_files(input_file, decrypted_file);
    printf("AES File:\t%s\n", file_compare_result ? "PASS" : "FAIL");

    // printf("\nFile decrypted successfully to %s\n", decrypted_file);

    // printf("\n===================================================\n\n");

    free(input_blocks);

    return 0;
}
