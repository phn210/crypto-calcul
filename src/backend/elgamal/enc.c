#include "conversion.h"
#include "elgamal.h"
#include "prime_gen.h"
#include "rng.h"

void setup(public_params_t *pp, sec_level_t level)
{
    mpz_inits(pp->p, pp->g, NULL);

    switch (level)
    {
    case L0:
        pp->p_bits = L0_P_BITS;
        hex_to_bigint(pp->p, L0_P);
        hex_to_bigint(pp->g, L0_G);
        break;
    case L1:
        pp->p_bits = L1_P_BITS;
        hex_to_bigint(pp->p, L1_P);
        hex_to_bigint(pp->g, L1_G);
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }
}

void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    mpz_inits(sk->x, pk->y, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(sk->x, state, pp->p);

    mpz_powm(pk->y, pp->g, sk->x, pp->p);

    gmp_randclear(state);
}

void crypto_encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t *pk, const public_params_t *pp)
{
    mpz_t k;
    mpz_inits(k, c1, c2, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(k, state, pp->p);
    mpz_powm(c1, pp->g, k, pp->p);
    mpz_powm(c2, pk->y, k, pp->p);
    mpz_mul(c2, c2, m);
    mpz_mod(c2, c2, pp->p);

    mpz_clear(k);
    gmp_randclear(state);
}

void crypto_decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t *sk, const public_params_t *pp)
{
    mpz_t s;
    mpz_init(s);

    mpz_powm(s, c1, sk->x, pp->p);
    mpz_invert(s, s, pp->p);
    mpz_mul(m, c2, s);
    mpz_mod(m, m, pp->p);

    mpz_clear(s);
}