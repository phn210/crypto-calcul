#ifndef MGF_H
#define MGF_H

#include "common.h"

void mgf1(unsigned char *mask, size_t mask_len, const unsigned char *seed, size_t seed_len, HASH_FUNCTION hash_function, SECURITY_LEVEL sec_level);

#endif