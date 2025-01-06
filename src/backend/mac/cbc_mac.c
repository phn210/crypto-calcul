#include "cbc_mac.h"
#include "conversion.h"

void cbc_mac(const void *key, size_t keysize, const void *data, size_t data_len, void *mac, sec_level_t sec_level)
{
    size_t key_len;
    switch (sec_level)
    {
    case L1:
        key_len = AES_KEY_SIZE_128;
        break;
    case L2:
        key_len = AES_KEY_SIZE_192;
        break;
    case L3:
        key_len = AES_KEY_SIZE_256;
        break;
    default:
        printf("Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    unsigned char *padded_message = pkcs7_padding(data, data_len, AES_BLOCK_SIZE);
    size_t padded_len = strlen(padded_message);
    unsigned char *key_hex = malloc(key_len);

    memset(key_hex, 0, key_len);
    string_to_hex(key_hex, key, keysize);

    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    unsigned char *input_blocks = malloc(padded_len);
    for (size_t i = 0; i < padded_len; i++)
    {
        input_blocks[i] = padded_message[i];
    }

    unsigned char *encrypted_ecb = malloc(padded_len);

    aes_encrypt_cbc(input_blocks, encrypted_ecb, iv, key_hex, padded_len, key_len);

    memcpy(mac, encrypted_ecb + padded_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}