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
// buf must hold count_bytes(num) bytes; leading zero bytes are not written
void bigint_to_bytes(unsigned char *buf, size_t *len, const mpz_t num, byte_order_t order);
// Writes num as exactly len big-endian bytes, left-padded with zeros (I2OSP)
CC_NODISCARD cc_status_t bigint_to_bytes_fixed(unsigned char *buf, size_t len, const mpz_t num);
// result must be initialized
cc_status_t hex_to_bigint(mpz_t result, const char *buf);
// *buf is allocated by GMP and must be released with free()
CC_NODISCARD cc_status_t bigint_to_hex(char **buf, const mpz_t num);
void string_to_hex(unsigned char *output, const char *input, size_t input_len);
CC_NODISCARD cc_status_t hex_to_string(char *output, const unsigned char *input, size_t input_len);
size_t count_bytes(const mpz_t n);

// *output is allocated and must be released with free()
CC_NODISCARD cc_status_t pkcs7_padding(const unsigned char *input, size_t len, unsigned char **output, size_t *out_len, size_t block_size);
CC_NODISCARD cc_status_t pkcs7_unpadding(const unsigned char *input, size_t len, unsigned char **output, size_t *out_len, size_t block_size);

#endif
