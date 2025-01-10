#ifndef CBC_MAC_H
#define CBC_MAC_H

#include "common.h"
#include "aes.h"

void cbc_mac(const void *key, size_t keysize, const void *data, size_t data_len, void *mac, sec_level_t sec_level);
int cbc_mac_verify(const void *key, size_t keysize, const void *data, size_t data_len, const void *mac, sec_level_t sec_level);
void cbc_mac_file(const char *filename, const void *key, size_t keysize, void *mac, sec_level_t sec_level);
int cbc_mac_file_verify(const char *filename, const void *key, size_t keysize, const void *mac, sec_level_t sec_level);

#endif