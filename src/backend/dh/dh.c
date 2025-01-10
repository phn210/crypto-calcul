#include "dh.h"
#include "conversion.h"
#include "rng.h"

void gen_secret(mpz_t s, const public_params_t pp)
{
    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(s, state, pp.p);
    gmp_randclear(state);
}

void gen_public(mpz_t p, const mpz_t secret, const public_params_t pp)
{
    mpz_powm(p, pp.g, secret, pp.p);
}

void compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t pp)
{
    mpz_powm(shared_secret, p, s, pp.p);
}
