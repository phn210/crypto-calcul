#ifndef RSA_H
#define RSA_H

#include "common.h"
#include "parameters.h"

// Security parameters for different security levels
#define L0_N_BITS 2048
#define L0_E "65537" // Common RSA public exponent

#define L1_N_BITS 3072
#define L1_E "65537"

typedef struct public_params
{
    int n_bits;
    mpz_t e;
} public_params_t;

typedef struct
{
    mpz_t n; // modulus
    mpz_t e; // public exponent
} pub_key;

typedef struct
{
    mpz_t p; // first prime
    mpz_t q; // second prime
    mpz_t d; // private exponent
} priv_key;

typedef struct
{
    mpz_t p;    // first prime factor
    mpz_t q;    // second prime factor
    mpz_t d;    // private exponent
    mpz_t dp;   // d mod (p-1)
    mpz_t dq;   // d mod (q-1)
    mpz_t qinv; // q^(-1) mod p
} priv_key_crt;

// Core RSA functions
void setup(public_params_t *pp, SECURITY_LEVEL level);

void keygen(priv_key *sk, pub_key *pk, public_params_t pp);
void encrypt(mpz_t c, const mpz_t m, const pub_key pk);
void decrypt(mpz_t m, const mpz_t c, const priv_key sk, const pub_key pk);
void sign(mpz_t s, const mpz_t m, const priv_key sk, const pub_key pk);
int verify(const mpz_t m, const mpz_t s, const pub_key pk);

void keygen_crt(priv_key_crt *sk, pub_key *pk, public_params_t pp);
void encrypt_crt(mpz_t c, const mpz_t m, const pub_key pk);
void decrypt_crt(mpz_t m, const mpz_t c, const priv_key_crt sk, const pub_key pk);
void sign_crt(mpz_t s, const mpz_t m, const priv_key_crt sk, const pub_key pk);
int verify_crt(const mpz_t m, const mpz_t s, const pub_key pk);

#endif