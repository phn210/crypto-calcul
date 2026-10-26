#ifndef ECDH_H
#define ECDH_H

#include "common.h"
#include "ecelgamal.h"

// Uses the EC-ElGamal curve parameters (ecelgamal_setup). Outputs must be initialized.
// Public values are point encodings (point_size(curve) bytes) read as big-endian integers.
CC_NODISCARD cc_status_t ecdh_gen_secret(mpz_t s, const public_params_t *pp);
CC_NODISCARD cc_status_t ecdh_gen_public(mpz_t p, const mpz_t s, const public_params_t *pp);
// Rejects peer values that do not encode a valid point of the curve
CC_NODISCARD cc_status_t ecdh_compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp);

#endif
