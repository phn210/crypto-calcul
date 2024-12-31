
#ifndef CONVERSION_H
#define CONVERSION_H

#include "common.h"

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len, BYTE_ORDER order);
void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, BYTE_ORDER order);
void hex_to_bigint(mpz_t result, const char *buf);
void bigint_to_hex(char **buf, const mpz_t num);
size_t count_bytes(const mpz_t n);

#endif