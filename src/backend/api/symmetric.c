#include "api_internal.h"
#include "aes.h"
#include "des.h"
#include "hmac.h"
#include "cbc_mac.h"

/* ------------------------------------------------------------------------- */
/* AES                                                                       */
/* ------------------------------------------------------------------------- */

typedef struct aes_params
{
    AES_MODE mode;
    AES_KEY_SIZE key_size;
    unsigned char key[AES_KEY_SIZE_256];
    unsigned char iv[AES_BLOCK_SIZE];
} aes_params_t;

// Validates the parameters and copies the key and IV (the internal functions take mutable pointers)
static cc_status_t aes_params(aes_params_t *p, cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv)
{
    switch (mode)
    {
    case CC_AES_ECB:
        p->mode = AES_MODE_ECB;
        break;
    case CC_AES_CBC:
        p->mode = AES_MODE_CBC;
        break;
    case CC_AES_CFB:
        p->mode = AES_MODE_CFB;
        break;
    case CC_AES_OFB:
        p->mode = AES_MODE_OFB;
        break;
    case CC_AES_CTR:
        p->mode = AES_MODE_CTR;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }
    if (key == NULL || (key_len != AES_KEY_SIZE_128 && key_len != AES_KEY_SIZE_192 && key_len != AES_KEY_SIZE_256))
        return CC_ERR_INVALID_ARG;
    if (iv == NULL && mode != CC_AES_ECB)
        return CC_ERR_INVALID_ARG;

    p->key_size = (AES_KEY_SIZE)key_len;
    memcpy(p->key, key, key_len);
    if (iv != NULL)
        memcpy(p->iv, iv, AES_BLOCK_SIZE);
    else
        memset(p->iv, 0, AES_BLOCK_SIZE);
    return CC_OK;
}

static cc_status_t aes_run(aes_params_t *p, unsigned char *in, unsigned char *out, size_t len, int encrypt)
{
    switch (p->mode)
    {
    case AES_MODE_ECB:
        return encrypt ? aes_encrypt_ecb(in, out, p->key, len, p->key_size) : aes_decrypt_ecb(in, out, p->key, len, p->key_size);
    case AES_MODE_CBC:
        return encrypt ? aes_encrypt_cbc(in, out, p->iv, p->key, len, p->key_size) : aes_decrypt_cbc(in, out, p->iv, p->key, len, p->key_size);
    case AES_MODE_CFB:
        return encrypt ? aes_encrypt_cfb(in, out, p->iv, p->key, len, p->key_size) : aes_decrypt_cfb(in, out, p->iv, p->key, len, p->key_size);
    case AES_MODE_OFB:
        return encrypt ? aes_encrypt_ofb(in, out, p->iv, p->key, len, p->key_size) : aes_decrypt_ofb(in, out, p->iv, p->key, len, p->key_size);
    default:
        return aes_ctr(in, out, p->iv, p->key, len, p->key_size);
    }
}

cc_status_t cc_aes_encrypt(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                           const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    aes_params_t p;
    CC_TRY(aes_params(&p, mode, key, key_len, iv));
    if (out_len == NULL || (in == NULL && in_len > 0))
        return CC_ERR_INVALID_ARG;

    size_t padded_len = in_len + AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE;
    size_t capacity = *out_len;
    *out_len = padded_len;
    if (out == NULL || capacity < padded_len)
        return CC_ERR_BUFFER_TOO_SMALL;

    unsigned char *padded;
    CC_TRY(pkcs7_padding(API_BYTES(in), in_len, &padded, &padded_len, AES_BLOCK_SIZE));
    cc_status_t status = aes_run(&p, padded, out, padded_len, 1);
    free(padded);
    return status;
}

cc_status_t cc_aes_decrypt(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                           const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    aes_params_t p;
    CC_TRY(aes_params(&p, mode, key, key_len, iv));
    if (out_len == NULL || in == NULL)
        return CC_ERR_INVALID_ARG;
    if (in_len == 0 || in_len % AES_BLOCK_SIZE != 0)
        return CC_ERR_INVALID_INPUT;

    unsigned char *copy = malloc(in_len);
    unsigned char *decrypted = malloc(in_len);
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    cc_status_t status = CC_OK;

    if (copy == NULL || decrypted == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
    {
        memcpy(copy, in, in_len);
        status = aes_run(&p, copy, decrypted, in_len, 0);
    }
    if (status == CC_OK)
        status = pkcs7_unpadding(decrypted, in_len, &plain, &plain_len, AES_BLOCK_SIZE);
    if (status == CC_OK)
        status = api_output(out, out_len, plain, plain_len);

    free(copy);
    free(decrypted);
    free(plain);
    return status;
}

cc_status_t cc_aes_encrypt_file(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                const char *in_path, const char *out_path)
{
    aes_params_t p;
    CC_TRY(aes_params(&p, mode, key, key_len, iv));
    if (in_path == NULL || out_path == NULL)
        return CC_ERR_INVALID_ARG;
    return aes_file_encrypt(in_path, out_path, p.key, p.iv, p.key_size, p.mode);
}

cc_status_t cc_aes_decrypt_file(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                const char *in_path, const char *out_path)
{
    aes_params_t p;
    CC_TRY(aes_params(&p, mode, key, key_len, iv));
    if (in_path == NULL || out_path == NULL)
        return CC_ERR_INVALID_ARG;
    return aes_file_decrypt(in_path, out_path, p.key, p.iv, p.key_size, p.mode);
}

/* ------------------------------------------------------------------------- */
/* DES                                                                       */
/* ------------------------------------------------------------------------- */

static uint64_t load_be64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | b[i];
    return v;
}

static void store_be64(uint8_t *b, uint64_t v)
{
    for (int i = 7; i >= 0; i--, v >>= 8)
        b[i] = (uint8_t)v;
}

// ECB over big-endian blocks; len is a multiple of 8
static cc_status_t des_blocks(const uint8_t key[8], const uint8_t *in, uint8_t *out, size_t len, des_mode_t mode)
{
    size_t nb_blocks = len / DES_BLOCK_SIZE;
    if (nb_blocks > 0x7FFFFFFF)
        return CC_ERR_INVALID_INPUT;

    uint64_t *blocks = malloc(nb_blocks * sizeof(uint64_t) + 1);
    if (blocks == NULL)
        return CC_ERR_NOMEM;

    for (size_t i = 0; i < nb_blocks; i++)
        blocks[i] = load_be64(in + 8 * i);
    des(blocks, blocks, load_be64(key), (int)nb_blocks, mode);
    for (size_t i = 0; i < nb_blocks; i++)
        store_be64(out + 8 * i, blocks[i]);

    free(blocks);
    return CC_OK;
}

cc_status_t cc_des_encrypt(const uint8_t key[8], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    if (key == NULL || out_len == NULL || (in == NULL && in_len > 0))
        return CC_ERR_INVALID_ARG;

    size_t padded_len = in_len + DES_BLOCK_SIZE - in_len % DES_BLOCK_SIZE;
    size_t capacity = *out_len;
    *out_len = padded_len;
    if (out == NULL || capacity < padded_len)
        return CC_ERR_BUFFER_TOO_SMALL;

    unsigned char *padded;
    CC_TRY(pkcs7_padding(API_BYTES(in), in_len, &padded, &padded_len, DES_BLOCK_SIZE));
    cc_status_t status = des_blocks(key, padded, out, padded_len, DES_ENCRYPT);
    free(padded);
    return status;
}

cc_status_t cc_des_decrypt(const uint8_t key[8], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    if (key == NULL || out_len == NULL || in == NULL)
        return CC_ERR_INVALID_ARG;
    if (in_len == 0 || in_len % DES_BLOCK_SIZE != 0)
        return CC_ERR_INVALID_INPUT;

    unsigned char *decrypted = malloc(in_len);
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    cc_status_t status = decrypted == NULL ? CC_ERR_NOMEM : des_blocks(key, in, decrypted, in_len, DES_DECRYPT);
    if (status == CC_OK)
        status = pkcs7_unpadding(decrypted, in_len, &plain, &plain_len, DES_BLOCK_SIZE);
    if (status == CC_OK)
        status = api_output(out, out_len, plain, plain_len);

    free(decrypted);
    free(plain);
    return status;
}

cc_status_t cc_des_encrypt_file(const uint8_t key[8], const char *in_path, const char *out_path)
{
    if (key == NULL || in_path == NULL || out_path == NULL)
        return CC_ERR_INVALID_ARG;
    return des_file(in_path, out_path, load_be64(key), DES_ENCRYPT);
}

cc_status_t cc_des_decrypt_file(const uint8_t key[8], const char *in_path, const char *out_path)
{
    if (key == NULL || in_path == NULL || out_path == NULL)
        return CC_ERR_INVALID_ARG;
    return des_file(in_path, out_path, load_be64(key), DES_DECRYPT);
}

/* ------------------------------------------------------------------------- */
/* MACs                                                                      */
/* ------------------------------------------------------------------------- */

static cc_status_t hmac_params(cc_hash_t hash, cc_sec_level_t level, sec_level_t *sec_level, hash_func_t *hash_function, size_t *len)
{
    CC_TRY(api_hash(hash, hash_function));
    // MD5 and SHA-1 ignore the level, but it must still be valid
    CC_TRY(api_sec_level(level, sec_level));
    return hmac_length(*sec_level, *hash_function, len);
}

static cc_status_t check_bytes(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len)
{
    return (key == NULL && key_len > 0) || (msg == NULL && msg_len > 0) ? CC_ERR_INVALID_ARG : CC_OK;
}

cc_status_t cc_hmac(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t *mac, size_t *mac_len)
{
    sec_level_t sec_level;
    hash_func_t hash_function;
    size_t len;
    CC_TRY(hmac_params(hash, level, &sec_level, &hash_function, &len));

    CC_TRY(check_bytes(key, key_len, msg, msg_len));

    unsigned char buf[64];
    CC_TRY(hmac(API_BYTES(key), key_len, API_BYTES(msg), msg_len, buf, sec_level, hash_function));
    return api_output(mac, mac_len, buf, len);
}

cc_status_t cc_hmac_verify(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                           const uint8_t *msg, size_t msg_len, const uint8_t *mac, size_t mac_len)
{
    sec_level_t sec_level;
    hash_func_t hash_function;
    size_t len;
    CC_TRY(hmac_params(hash, level, &sec_level, &hash_function, &len));
    CC_TRY(check_bytes(key, key_len, msg, msg_len));
    if (mac == NULL)
        return CC_ERR_INVALID_ARG;
    return hmac_verify(API_BYTES(key), key_len, API_BYTES(msg), msg_len, mac, mac_len, sec_level, hash_function);
}

cc_status_t cc_hmac_file(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                         const char *path, uint8_t *mac, size_t *mac_len)
{
    sec_level_t sec_level;
    hash_func_t hash_function;
    size_t len;
    CC_TRY(hmac_params(hash, level, &sec_level, &hash_function, &len));
    CC_TRY(check_bytes(key, key_len, NULL, 0));
    if (path == NULL)
        return CC_ERR_INVALID_ARG;

    unsigned char buf[64];
    CC_TRY(hmac_file(path, API_BYTES(key), key_len, buf, sec_level, hash_function));
    return api_output(mac, mac_len, buf, len);
}

cc_status_t cc_cbc_mac(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t *mac, size_t *mac_len)
{
    sec_level_t sec_level;
    CC_TRY(api_sec_level(level, &sec_level));

    CC_TRY(check_bytes(key, key_len, msg, msg_len));

    unsigned char buf[AES_BLOCK_SIZE];
    CC_TRY(cbc_mac(API_BYTES(key), key_len, API_BYTES(msg), msg_len, buf, sec_level));
    return api_output(mac, mac_len, buf, AES_BLOCK_SIZE);
}

cc_status_t cc_cbc_mac_verify(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                              const uint8_t *msg, size_t msg_len, const uint8_t *mac, size_t mac_len)
{
    sec_level_t sec_level;
    CC_TRY(api_sec_level(level, &sec_level));
    CC_TRY(check_bytes(key, key_len, msg, msg_len));
    if (mac == NULL)
        return CC_ERR_INVALID_ARG;
    return cbc_mac_verify(API_BYTES(key), key_len, API_BYTES(msg), msg_len, mac, mac_len, sec_level);
}

cc_status_t cc_cbc_mac_file(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                            const char *path, uint8_t *mac, size_t *mac_len)
{
    sec_level_t sec_level;
    CC_TRY(api_sec_level(level, &sec_level));
    CC_TRY(check_bytes(key, key_len, NULL, 0));
    if (path == NULL)
        return CC_ERR_INVALID_ARG;

    unsigned char buf[AES_BLOCK_SIZE];
    CC_TRY(cbc_mac_file(path, API_BYTES(key), key_len, buf, sec_level));
    return api_output(mac, mac_len, buf, AES_BLOCK_SIZE);
}
