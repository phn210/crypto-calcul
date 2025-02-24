#ifndef ECELGAMAL_H
#define ECELGAMAL_H

#include "common.h"
#include "ec.h"

typedef struct public_params
{
    curve_t curve;
} public_params_t;

typedef struct priv_key
{
    mpz_t x;
} priv_key_t;

typedef struct pub_key
{
    point_t Y;
} pub_key_t;

void setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id);
void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp);
void crypto_encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);
void crypto_decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);
void crypto_sign(mpz_t s1, mpz_t s2, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);
char crypto_verify(const mpz_t s1, const mpz_t s2, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);

#endif