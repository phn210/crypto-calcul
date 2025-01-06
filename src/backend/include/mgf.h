#ifndef MGF_H
#define MGF_H

#include "common.h"

void mgf1(unsigned char *mask, size_t mask_len, const unsigned char *seed, size_t seed_len, hash_func_t hash_function, sec_level_t sec_level);

#endif