#ifndef DH_H
#define DH_H

#include "common.h"
#include "elgamal.h"

// Uses the ElGamal group parameters (elgamal_setup). Outputs must be initialized.
CC_NODISCARD cc_status_t dh_gen_secret(mpz_t s, const public_params_t *pp);
CC_NODISCARD cc_status_t dh_gen_public(mpz_t p, const mpz_t secret, const public_params_t *pp);
// Rejects peer public values outside [2, p - 2], which would force a trivial shared secret
CC_NODISCARD cc_status_t dh_compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp);

#endif
