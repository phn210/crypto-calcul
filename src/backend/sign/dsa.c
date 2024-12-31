#include "dsa.h"
#include "prime_gen.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"
#include "sha3.h"

void setup(public_params_t *pp, SECURITY_LEVEL level, HASH_FUNCTION hash)
{
    mpz_t tmp;
    mpz_inits(tmp, pp->p, pp->q, pp->g, NULL);

    switch (level)
    {
    case L0:
        pp->p_bits = L0_L;
        pp->q_bits = L0_N;
        pp->md_len = 28;
        hex_to_bigint(pp->p, L0_P);
        hex_to_bigint(pp->q, L0_Q);
        hex_to_bigint(pp->g, L0_G);
        break;
    default: // L1
        pp->p_bits = L1_L;
        pp->q_bits = L1_N;
        pp->md_len = 32;
        hex_to_bigint(pp->p, L1_P);
        hex_to_bigint(pp->q, L1_Q);
        hex_to_bigint(pp->g, L1_G);
        break;
    }
    switch (hash)
    {
    case SHA2:
        /* code */
        break;

    default: // SHA3
        pp->hash = sha3;
        break;
    }
}

void keygen(priv_key_t *sk, pub_key_t *pk, public_params_t pp)
{
    mpz_inits(sk->x, pk->y, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(sk->x, state, pp.q);

    mpz_powm(pk->y, pp.g, sk->x, pp.p);
}

void sign(mpz_t r, mpz_t s, const unsigned char *m, int len, priv_key_t sk, public_params_t pp)
{

    mpz_t hm, k, tmp;
    mpz_inits(hm, k, tmp, r, s, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(k, state, pp.q);
    unsigned char *md = (unsigned char *)malloc(pp.md_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    pp.hash(m, len, md, pp.md_len);
    // printf("%d\n", pp.md_len);
    bytes_to_bigint(hm, md, pp.md_len, BIG_ENDIAN);

    mpz_powm(r, pp.g, k, pp.p);
    mpz_mod(r, r, pp.q);

    mpz_mul(tmp, sk.x, r);
    mpz_add(tmp, tmp, hm);
    mpz_invert(k, k, pp.q);
    mpz_mul(s, tmp, k);
    mpz_mod(s, s, pp.q);

    mpz_clears(hm, k, tmp, NULL);
}

char verify(const mpz_t r, const mpz_t s, const unsigned char *m, int len, pub_key_t pk, public_params_t pp)
{
    if (mpz_cmp_ui(r, 0) == 0 || mpz_cmp(r, pp.q) >= 0 || mpz_cmp_ui(s, 0) == 0 || mpz_cmp(s, pp.q) >= 0)
        return 0;

    mpz_t hm, w, u1, u2, v;
    mpz_inits(hm, w, u1, u2, v, NULL);

    unsigned char *md = (unsigned char *)malloc(pp.md_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    pp.hash(m, len, md, pp.md_len);
    bytes_to_bigint(hm, md, pp.md_len, BIG_ENDIAN);

    mpz_invert(w, s, pp.q);
    mpz_mul(u1, hm, w);
    mpz_mod(u1, u1, pp.q);
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, pp.q);

    mpz_powm(u1, pp.g, u1, pp.p);
    mpz_powm(u2, pk.y, u2, pp.p);
    mpz_mul(v, u1, u2);
    mpz_mod(v, v, pp.p);
    mpz_mod(v, v, pp.q);

    int res = mpz_cmp(v, r) == 0;
    mpz_clears(hm, w, u1, u2, v, NULL);

    return res;
}