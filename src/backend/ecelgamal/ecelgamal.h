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

// Setup and key generation initialize their outputs only on success
CC_NODISCARD cc_status_t ecelgamal_setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id);
CC_NODISCARD cc_status_t ecelgamal_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp);
void ecelgamal_free_params(public_params_t *pp);
void ecelgamal_free_keys(priv_key_t *sk, pub_key_t *pk);

// Hashed EC-ElGamal: c1 = kG (point_size(curve) bytes), c2 = m XOR H(kY) (m_len bytes).
// Messages are at most curve.md_len bytes; the decrypted message is c2_len bytes.
CC_NODISCARD cc_status_t ecelgamal_encrypt(unsigned char *c1, unsigned char *c2, const unsigned char *m, size_t m_len,
                                           const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);
CC_NODISCARD cc_status_t ecelgamal_decrypt(unsigned char *m, const unsigned char *c1, size_t c1_len, const unsigned char *c2, size_t c2_len,
                                           const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);

// Signatures need point addition, which Montgomery curves do not support (CC_ERR_UNSUPPORTED)
CC_NODISCARD cc_status_t ecelgamal_sign(mpz_t s1, mpz_t s2, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);
// Returns CC_OK if the signature is valid, CC_ERR_VERIFY otherwise
CC_NODISCARD cc_status_t ecelgamal_verify(const mpz_t s1, const mpz_t s2, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);

#endif
