#include "conversion.h"
#include "elgamal.h"
#include "prime_gen.h"
#include "rng.h"

void keygen(priv_key *sk, pub_key *pk)
{
    gmp_randstate_t state;
    rng_init(state);

    mpz_inits(sk->x, pk->p, pk->g, pk->y, NULL);

    hex_to_bigint(pk->p, P);
    hex_to_bigint(pk->g, G);

    gen_prime_m(sk->x, state, pk->p, 100, 25, GMP_TEST);

    mpz_powm(pk->y, pk->g, sk->x, pk->p);
}

void encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key pk)
{
    gmp_randstate_t state;
    rng_init(state);

    mpz_t k;
    mpz_inits(k, c1, c2, NULL);

    rand_int_m(k, state, pk.p);
    mpz_powm(c1, pk.g, k, pk.p);
    mpz_powm(c2, pk.y, k, pk.p);
    mpz_mul(c2, c2, m);
    mpz_mod(c2, c2, pk.p);

    mpz_clear(k);
}

void decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key sk, const pub_key pk)
{
    mpz_t s;
    mpz_init(s);

    mpz_powm(s, c1, sk.x, pk.p);
    mpz_invert(s, s, pk.p);
    mpz_mul(m, c2, s);
    mpz_mod(m, m, pk.p);

    mpz_clear(s);
}