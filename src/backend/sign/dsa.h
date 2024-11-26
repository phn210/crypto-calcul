#ifndef SIGN_DSA_H
#define SIGN_DSA_H

#include "common.h"

typedef struct public_params
{
    int p_bits;
    int q_bits;
    mpz_t p;
    mpz_t q;
    mpz_t g;
    int md_len;
    void *(*hash)(const void *, size_t, void *, int);
} public_params_t;

typedef struct pub_key
{
    mpz_t y;
} pub_key_t;

typedef struct priv_key
{
    mpz_t x;
} priv_key_t;

void setup(public_params_t *pp, SECURITY_LEVEL level, HASH_FUNCTION hash);
void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp);
void sign(mpz_t r, mpz_t s, const unsigned char *m, const int len, const priv_key_t sk, const public_params_t pp);
char verify(const mpz_t r, const mpz_t s, const unsigned char *m, const int len, const pub_key_t pk, const public_params_t pp);

#endif