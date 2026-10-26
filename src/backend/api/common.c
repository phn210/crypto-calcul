#include "api_internal.h"
#include "ec.h"

cc_status_t api_output(uint8_t *out, size_t *out_len, const void *data, size_t len)
{
    if (out_len == NULL)
        return CC_ERR_INVALID_ARG;
    size_t capacity = *out_len;
    *out_len = len;
    if (out == NULL || capacity < len)
        return CC_ERR_BUFFER_TOO_SMALL;
    if (len > 0)
        memcpy(out, data, len);
    return CC_OK;
}

static size_t mpz_output_size(const mpz_t n)
{
    return mpz_sgn(n) == 0 ? 1 : count_bytes(n);
}

cc_status_t api_output_mpz(uint8_t *out, size_t *out_len, const mpz_t n)
{
    if (out_len == NULL)
        return CC_ERR_INVALID_ARG;
    if (mpz_sgn(n) < 0)
        return CC_ERR_INVALID_INPUT;

    size_t len = mpz_output_size(n);
    size_t capacity = *out_len;
    *out_len = len;
    if (out == NULL || capacity < len)
        return CC_ERR_BUFFER_TOO_SMALL;
    return bigint_to_bytes_fixed(out, len, n);
}

cc_status_t api_output_mpz_pair(uint8_t *a, size_t *a_len, const mpz_t x, uint8_t *b, size_t *b_len, const mpz_t y)
{
    if (a_len == NULL || b_len == NULL)
        return CC_ERR_INVALID_ARG;

    size_t a_capacity = *a_len, b_capacity = *b_len;
    *a_len = mpz_output_size(x);
    *b_len = mpz_output_size(y);
    if (a == NULL || b == NULL || a_capacity < *a_len || b_capacity < *b_len)
        return CC_ERR_BUFFER_TOO_SMALL;

    CC_TRY(api_output_mpz(a, &a_capacity, x));
    return api_output_mpz(b, &b_capacity, y);
}

void api_input_mpz(mpz_t n, const uint8_t *in, size_t in_len)
{
    if (in == NULL || in_len == 0)
        mpz_set_ui(n, 0);
    else
        bytes_to_bigint(n, in, in_len, BIG);
}

cc_status_t api_sec_level(cc_sec_level_t level, sec_level_t *internal)
{
    switch (level)
    {
    case CC_SEC_112:
        *internal = L0;
        return CC_OK;
    case CC_SEC_128:
        *internal = L1;
        return CC_OK;
    case CC_SEC_192:
        *internal = L2;
        return CC_OK;
    case CC_SEC_256:
        *internal = L3;
        return CC_OK;
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t api_hash(cc_hash_t hash, hash_func_t *internal)
{
    switch (hash)
    {
    case CC_HASH_MD5:
        *internal = MD5;
        return CC_OK;
    case CC_HASH_SHA1:
        *internal = SHA1;
        return CC_OK;
    case CC_HASH_SHA2:
        *internal = SHA2;
        return CC_OK;
    case CC_HASH_SHA3:
        *internal = SHA3;
        return CC_OK;
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t api_curve(cc_curve_t curve, int *type, unsigned char *id)
{
    switch (curve)
    {
    case CC_CURVE_P224:
        *type = WEIERSTRASS, *id = P224;
        return CC_OK;
    case CC_CURVE_P256:
        *type = WEIERSTRASS, *id = P256;
        return CC_OK;
    case CC_CURVE_P384:
        *type = WEIERSTRASS, *id = P384;
        return CC_OK;
    case CC_CURVE_P521:
        *type = WEIERSTRASS, *id = P521;
        return CC_OK;
    case CC_CURVE_SECP256K1:
        *type = WEIERSTRASS, *id = P256K1;
        return CC_OK;
    case CC_CURVE_W25519:
        *type = WEIERSTRASS, *id = W25519;
        return CC_OK;
    case CC_CURVE_W448:
        *type = WEIERSTRASS, *id = W448;
        return CC_OK;
    case CC_CURVE_25519:
        *type = MONTGOMERY, *id = C25519;
        return CC_OK;
    case CC_CURVE_448:
        *type = MONTGOMERY, *id = C448;
        return CC_OK;
    case CC_CURVE_ED25519:
        *type = EDWARDS, *id = ED25519;
        return CC_OK;
    case CC_CURVE_ED448:
        *type = EDWARDS, *id = ED448;
        return CC_OK;
    case CC_CURVE_E448:
        *type = EDWARDS, *id = E448;
        return CC_OK;
    }
    return CC_ERR_INVALID_ARG;
}
