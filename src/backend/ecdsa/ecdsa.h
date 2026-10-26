#ifndef ECDSA_H
#define ECDSA_H

#include "common.h"
#include "ec.h"

typedef struct public_params
{
    curve_t curve;
} public_params_t;

typedef struct priv_key
{
    mpz_t d;
} priv_key_t;

typedef struct pub_key
{
    point_t Q;
} pub_key_t;

// Setup and key generation initialize their outputs only on success
CC_NODISCARD cc_status_t ecdsa_setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id);
CC_NODISCARD cc_status_t ecdsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp);
void ecdsa_free_params(public_params_t *pp);
void ecdsa_free_keys(priv_key_t *sk, pub_key_t *pk);

// Montgomery curves are not supported (CC_ERR_UNSUPPORTED); r and s must be initialized
CC_NODISCARD cc_status_t ecdsa_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function);
// Returns CC_OK if the signature is valid, CC_ERR_VERIFY otherwise
CC_NODISCARD cc_status_t ecdsa_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function);

#endif
