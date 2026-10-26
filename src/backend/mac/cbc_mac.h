#ifndef CBC_MAC_H
#define CBC_MAC_H

#include "common.h"
#include "aes.h"

// AES-CBC-MAC (zero IV, PKCS#7 padding); the AES key size follows the security level (L1-L3).
// The key is truncated or zero-padded to the AES key size. mac must hold AES_BLOCK_SIZE bytes.
CC_NODISCARD cc_status_t cbc_mac(const void *key, size_t keysize, const void *data, size_t data_len, void *mac, sec_level_t sec_level);
// Returns CC_OK if the MAC matches, CC_ERR_VERIFY otherwise
CC_NODISCARD cc_status_t cbc_mac_verify(const void *key, size_t keysize, const void *data, size_t data_len, const void *mac, size_t mac_len, sec_level_t sec_level);
CC_NODISCARD cc_status_t cbc_mac_file(const char *filename, const void *key, size_t keysize, void *mac, sec_level_t sec_level);
CC_NODISCARD cc_status_t cbc_mac_file_verify(const char *filename, const void *key, size_t keysize, const void *mac, size_t mac_len, sec_level_t sec_level);

#endif
