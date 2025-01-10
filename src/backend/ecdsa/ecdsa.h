#ifndef ECDSA_H
#define ECDSA_H

#include "common.h"
#include "ec.h"

typedef struct public_params
{
    curve_t curve;
} public_params_t;

typedef struct priv_key
{
    mpz_t d;
} priv_key_t;

typedef struct pub_key
{
    point_t Q;
} pub_key_t;

void setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id);
void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp);
void crypto_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);
int crypto_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);

#endif