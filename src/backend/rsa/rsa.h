#ifndef RSA_H
#define RSA_H

#include "common.h"

// Security parameters for different security levels
#define L0_N_BITS 2048
#define L0_E "65537" // Common RSA public exponent

#define L1_N_BITS 3072
#define L1_E "65537"

#define L2_N_BITS 7680
#define L2_E "65537"

#define L3_N_BITS 15360
#define L3_E "65537"

typedef enum
{
    RSA_STANDARD,
    RSA_CRT
} rsa_algo_t;

typedef struct public_params
{
    int n_bits;
    mpz_t e;
} public_params_t;

typedef struct pub_key
{
    mpz_t n; // modulus
    mpz_t e; // public exponent
} pub_key_t;

typedef struct priv_key
{
    mpz_t n;     // modulus
    mpz_t p;     // first prime factor
    mpz_t q;     // second prime factor
    mpz_t d;     // private exponent
    mpz_t dp;    // d mod (p-1)
    mpz_t dq;    // d mod (q-1)
    mpz_t q_inv; // q^(-1) mod p
} priv_key_t;

// Core RSA functions
void setup(public_params_t *pp, sec_level_t level);

void keygen(priv_key_t *sk, pub_key_t *pk, public_params_t pp);

void crypto_encrypt(mpz_t c, const mpz_t m, const pub_key_t *pk);
void crypto_decrypt(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm);
void crypto_sign(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm);
int crypto_verify(const mpz_t m, const mpz_t s, const pub_key_t *pk);

void crypto_encrypt_pkcs1(mpz_t c, const mpz_t m, const pub_key_t *pk);
void crypto_decrypt_pkcs1(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm);
void crypto_sign_pkcs1(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
int crypto_verify_pkcs1(const mpz_t m, const mpz_t s, const pub_key_t *pk, sec_level_t sec_level);

void crypto_encrypt_oaep(mpz_t c, const mpz_t m, const pub_key_t *pk, sec_level_t sec_level);
void crypto_decrypt_oaep(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
void crypto_sign_pss(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
int crypto_verify_pss(const mpz_t m, const mpz_t s, const pub_key_t *pk, sec_level_t sec_level);

#endif