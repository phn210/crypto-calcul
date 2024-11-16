#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

void hex_to_bigint(mpz_t result, const char *buf);
void bigint_to_hex(char **buf, const mpz_t num);