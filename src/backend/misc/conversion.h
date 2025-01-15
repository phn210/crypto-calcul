
#ifndef CONVERSION_H
#define CONVERSION_H

#include "common.h"

typedef enum byte_order
{
    NATIVE,
    BIG,
    LITTLE
} byte_order_t;

void bytes_to_bigint(mpz_t result, const unsigned char *buf, size_t len, byte_order_t order);
void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, byte_order_t order);
void hex_to_bigint(mpz_t result, const char *buf);
void bigint_to_hex(char **buf, const mpz_t num);
void string_to_hex(unsigned char *output, const char *input, size_t input_len);
void hex_to_string(char *output, const unsigned char *input, size_t input_len);
size_t count_bytes(const mpz_t n);

unsigned char *pkcs7_padding(unsigned char *input, size_t len, size_t *out_len, size_t block_size);
unsigned char *pkcs7_unpadding(unsigned char *input, size_t len, size_t *out_len, size_t block_size);

#endif