#ifndef ECDH_H
#define ECDH_H

#include "common.h"
#include "ecelgamal.h"

void gen_secret(mpz_t s, const public_params_t *pp);
void gen_public(mpz_t p, const mpz_t s, const public_params_t *pp);
void compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp);

#endif