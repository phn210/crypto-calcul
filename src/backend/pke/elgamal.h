#ifndef PKE_ELGAMAL_H
#define PKE_ELGAMAL_H

#include "common.h"

typedef struct public_params
{
    int p_bits;
    mpz_t p;
    mpz_t g;
} public_params_t;

typedef struct pub_key
{
    mpz_t y;
} pub_key_t;

typedef struct priv_key
{
    mpz_t x;
} priv_key_t;

void setup(public_params_t *pp, SECURITY_LEVEL level);
void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp);
void encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t pk, const public_params_t pp);
void decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t sk, const public_params_t pp);

#endif