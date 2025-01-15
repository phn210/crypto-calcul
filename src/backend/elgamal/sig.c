#include "elgamal.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"

void crypto_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, sec_level_t sec_level)
{
    size_t hash_len;
    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    mpz_t k, k_inv, h, p1, tmp;
    mpz_inits(k, k_inv, h, p1, tmp, NULL);

    gmp_randstate_t state;
    rng_init(state);
    mpz_sub_ui(p1, pp->p, 1);

    int invertible;
    do
    {
        rand_int_m(k, state, p1);
        invertible = mpz_invert(k_inv, k, p1);
    } while (invertible == 0);

    // r = g^k mod p
    mpz_powm(r, pp->g, k, pp->p);

    // h = H(m)
    unsigned char *md = (unsigned char *)malloc(hash_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    sha2(m, m_len, md, hash_len);
    bytes_to_bigint(h, md, hash_len, BIG);

    // s = k^-1 * (h - r * x) mod (p - 1)
    mpz_mul(tmp, r, sk->x);
    mpz_sub(tmp, h, tmp);
    mpz_mul(s, k_inv, tmp);
    mpz_mod(s, s, p1);

    // mpz_powm(tmp, pp->g, h, pp->p);
    // gmp_printf("tmp: %Zd\n", tmp);

    mpz_clears(k, k_inv, h, p1, tmp, NULL);
    free(md);
}

int crypto_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, sec_level_t sec_level)
{
    size_t hash_len;
    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    mpz_t h, v1, v2, tmp;
    mpz_inits(h, v1, v2, tmp, NULL);

    // h = H(m)
    unsigned char *md = (unsigned char *)malloc(hash_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    sha2(m, m_len, md, hash_len);
    bytes_to_bigint(h, md, hash_len, BIG);

    // v1 = y^r * r^s mod p
    mpz_powm(v1, pk->y, r, pp->p);
    mpz_powm(tmp, r, s, pp->p);
    mpz_mul(v1, v1, tmp);
    mpz_mod(v1, v1, pp->p);

    // v2 = g^h mod p
    mpz_powm(v2, pp->g, h, pp->p);
    mpz_mod(v2, v2, pp->p);

    int result = mpz_cmp(v1, v2) == 0;

    mpz_clears(h, v1, v2, tmp, NULL);
    free(md);

    return result;
}