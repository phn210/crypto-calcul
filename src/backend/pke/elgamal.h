#ifndef PKE_ELGAMAL_H
#define PKE_ELGAMAL_H

#include "common.h"
#include "parameters.h"

typedef struct
{
    int p_bits;
    mpz_t p;
    mpz_t g;
} public_params;

typedef struct
{
    mpz_t y;
} pub_key;

typedef struct
{
    mpz_t x;
} priv_key;

void setup(public_params *pp, SECURITY_LEVEL level);
void keygen(priv_key *sk, pub_key *pk, const public_params pp);
void encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key pk, const public_params pp);
void decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key sk, const public_params pp);

#endif