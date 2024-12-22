#ifndef PKE_RSACRT_SIG_H
#define PKE_RSACRT_SIG_H

#include "common.h"
#include "parameters.h"

// Security parameters for different security levels
#if PARAM_SECURITY == 112
#define N_BITS 2048
#define E "65537"  // Common RSA public exponent
#endif

#if PARAM_SECURITY == 128
#define N_BITS 3072
#define E "65537"
#endif

typedef struct {
    mpz_t n;  // modulus
    mpz_t e;  // public exponent
} pub_key;

typedef struct {
    mpz_t p;     // first prime factor
    mpz_t q;     // second prime factor
    mpz_t d;     // private exponent
    mpz_t dp;    // d mod (p-1)
    mpz_t dq;    // d mod (q-1)
    mpz_t qinv;  // q^(-1) mod p
} priv_key;

void keygen(priv_key *sk, pub_key *pk);
void sign(mpz_t s, const mpz_t m, const priv_key sk, const pub_key pk);
int verify(const mpz_t m, const mpz_t s, const pub_key pk);

#endif