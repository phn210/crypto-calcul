#ifndef CONVERSION_H
#define CONVERSION_H

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len);
void hex_to_bigint(mpz_t result, const char *buf);
void bigint_to_hex(char **buf, const mpz_t num);

#endif