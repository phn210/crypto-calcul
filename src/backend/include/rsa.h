#ifndef PKE_RSA_H
#define PKE_RSA_H

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
    mpz_t p;  // first prime
    mpz_t q;  // second prime
    mpz_t d;  // private exponent
} priv_key;

// Core RSA functions
void keygen(priv_key *sk, pub_key *pk);
void encrypt(mpz_t c, const mpz_t m, const pub_key pk);
void decrypt(mpz_t m, const mpz_t c, const priv_key sk, const pub_key pk);

#endif