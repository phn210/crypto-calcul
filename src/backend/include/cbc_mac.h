#ifndef CBC_MAC_H
#define CBC_MAC_H

#include "common.h"
#include "aes.h"

void cbc_mac(const void *key, size_t keysize, const void *data, size_t data_len, void *mac, sec_level_t sec_level);

#endif