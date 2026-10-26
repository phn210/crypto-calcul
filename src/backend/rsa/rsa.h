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

// Setup and key generation initialize their outputs only on success
CC_NODISCARD cc_status_t rsa_setup(public_params_t *pp, sec_level_t level);
CC_NODISCARD cc_status_t rsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp);
void rsa_free_params(public_params_t *pp);
void rsa_free_keys(priv_key_t *sk, pub_key_t *pk);

// Size in bytes of the modulus: the length of ciphertexts and signatures of the padded schemes
size_t rsa_modulus_size(const mpz_t n);
// SHA-2 output length used by the padded schemes at this security level
CC_NODISCARD cc_status_t rsa_hash_length(sec_level_t sec_level, size_t *hash_len);

// Raw RSA primitives: x^e mod n and x^d mod n, for 0 <= x < n
void rsa_public_op(mpz_t r, const mpz_t x, const pub_key_t *pk);
CC_NODISCARD cc_status_t rsa_private_op(mpz_t r, const mpz_t x, const priv_key_t *sk, rsa_algo_t algorithm);

// Textbook RSA on integers in [0, n)
CC_NODISCARD cc_status_t rsa_encrypt(mpz_t c, const mpz_t m, const pub_key_t *pk);
CC_NODISCARD cc_status_t rsa_decrypt(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm);
CC_NODISCARD cc_status_t rsa_sign(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm);
// Returns CC_OK if the signature is valid, CC_ERR_VERIFY otherwise
CC_NODISCARD cc_status_t rsa_verify(const mpz_t m, const mpz_t s, const pub_key_t *pk);

// Padded schemes work on byte strings. Ciphertexts and signatures are rsa_modulus_size(n) bytes;
// decrypted messages are at most that long.
CC_NODISCARD cc_status_t rsa_encrypt_pkcs1(unsigned char *c, const unsigned char *m, size_t m_len, const pub_key_t *pk);
CC_NODISCARD cc_status_t rsa_decrypt_pkcs1(unsigned char *m, size_t *m_len, const unsigned char *c, size_t c_len, const priv_key_t *sk, rsa_algo_t algorithm);
CC_NODISCARD cc_status_t rsa_sign_pkcs1(unsigned char *s, const unsigned char *m, size_t m_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
CC_NODISCARD cc_status_t rsa_verify_pkcs1(const unsigned char *m, size_t m_len, const unsigned char *s, size_t s_len, const pub_key_t *pk, sec_level_t sec_level);

CC_NODISCARD cc_status_t rsa_encrypt_oaep(unsigned char *c, const unsigned char *m, size_t m_len, const pub_key_t *pk, sec_level_t sec_level);
CC_NODISCARD cc_status_t rsa_decrypt_oaep(unsigned char *m, size_t *m_len, const unsigned char *c, size_t c_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
CC_NODISCARD cc_status_t rsa_sign_pss(unsigned char *s, const unsigned char *m, size_t m_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level);
CC_NODISCARD cc_status_t rsa_verify_pss(const unsigned char *m, size_t m_len, const unsigned char *s, size_t s_len, const pub_key_t *pk, sec_level_t sec_level);

#endif
