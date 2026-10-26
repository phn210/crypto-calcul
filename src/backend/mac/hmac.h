#ifndef HMAC_H
#define HMAC_H

#include "common.h"

typedef struct hmac_ctx
{
    size_t b;
    size_t l;
    unsigned char *key;
    unsigned char *i_key_pad;
    unsigned char *o_key_pad;
    unsigned char *out;
    void *(*hash)(const void *, size_t, void *, size_t);
} hmac_ctx_t;

// Length of the MAC produced for this security level and hash function
CC_NODISCARD cc_status_t hmac_length(sec_level_t sec_level, hash_func_t hash_function, size_t *mac_len);

// On failure, hmac_init leaves nothing to free
CC_NODISCARD cc_status_t hmac_init(hmac_ctx_t *ctx, const void *key, size_t key_len, sec_level_t sec_level, hash_func_t hash_function);
CC_NODISCARD cc_status_t hmac_update(hmac_ctx_t *ctx, const void *data, size_t data_len);
void hmac_final(hmac_ctx_t *ctx, void *mac);
void hmac_free(hmac_ctx_t *ctx);

// mac must hold hmac_length() bytes
CC_NODISCARD cc_status_t hmac(const void *key, size_t keysize, const void *data, size_t data_len,
                              void *mac, sec_level_t sec_level, hash_func_t hash_function);
// Returns CC_OK if the MAC matches, CC_ERR_VERIFY otherwise
CC_NODISCARD cc_status_t hmac_verify(const void *key, size_t keysize, const void *data, size_t data_len,
                                     const void *mac, size_t mac_len, sec_level_t sec_level, hash_func_t hash_function);
CC_NODISCARD cc_status_t hmac_file(const char *filename, const void *key, size_t keysize,
                                   void *mac, sec_level_t sec_level, hash_func_t hash_function);
CC_NODISCARD cc_status_t hmac_file_verify(const char *filename, const void *key, size_t keysize,
                                          const void *mac, size_t mac_len, sec_level_t sec_level, hash_func_t hash_function);

// Constant-time comparison: 0 if equal
int ct_memcmp(const void *a, const void *b, size_t len);

#endif
