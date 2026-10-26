#include "cbc_mac.h"
#include "hmac.h"
#include "conversion.h"
#include "file_io.h"

cc_status_t cbc_mac(const void *key, size_t keysize, const void *data, size_t data_len, void *mac, sec_level_t sec_level)
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
        return CC_ERR_INVALID_ARG;
    }

    unsigned char key_block[AES_KEY_SIZE_256];
    memset(key_block, 0, sizeof(key_block));
    memcpy(key_block, key, keysize < key_len ? keysize : key_len);

    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    // aes_encrypt_cbc works in place on its input, so it gets the padded copy
    unsigned char *padded_message;
    size_t padded_len;
    CC_TRY(pkcs7_padding(data, data_len, &padded_message, &padded_len, AES_BLOCK_SIZE));

    cc_status_t status = CC_OK;
    unsigned char *encrypted = malloc(padded_len);
    if (encrypted == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
        status = aes_encrypt_cbc(padded_message, encrypted, iv, key_block, padded_len, key_len);
    if (status == CC_OK)
        memcpy(mac, encrypted + padded_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    free(padded_message);
    free(encrypted);
    return status;
}

cc_status_t cbc_mac_verify(const void *key, size_t keysize, const void *data, size_t data_len, const void *mac, size_t mac_len, sec_level_t sec_level)
{
    unsigned char mac_check[AES_BLOCK_SIZE];
    CC_TRY(cbc_mac(key, keysize, data, data_len, mac_check, sec_level));
    if (mac_len != AES_BLOCK_SIZE)
        return CC_ERR_VERIFY;
    return ct_memcmp(mac, mac_check, AES_BLOCK_SIZE) == 0 ? CC_OK : CC_ERR_VERIFY;
}

cc_status_t cbc_mac_file(const char *filename, const void *key, size_t keysize, void *mac, sec_level_t sec_level)
{
    unsigned char *file_contents;
    size_t file_size;
    CC_TRY(read_file(filename, &file_contents, &file_size));

    cc_status_t status = cbc_mac(key, keysize, file_contents, file_size, mac, sec_level);
    free(file_contents);
    return status;
}

cc_status_t cbc_mac_file_verify(const char *filename, const void *key, size_t keysize, const void *mac, size_t mac_len, sec_level_t sec_level)
{
    unsigned char *file_contents;
    size_t file_size;
    CC_TRY(read_file(filename, &file_contents, &file_size));

    cc_status_t status = cbc_mac_verify(key, keysize, file_contents, file_size, mac, mac_len, sec_level);
    free(file_contents);
    return status;
}
