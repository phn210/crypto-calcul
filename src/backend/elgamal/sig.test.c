#include "elgamal.h"

void test_setup(public_params_t *pp, sec_level_t level)
{
    setup(pp, level);
    // gmp_printf("Public Parameters (p): %Zd\n", pp->p);
    // gmp_printf("Public Parameters (g): %Zd\n", pp->g);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    keygen(sk, pk, pp);

    // gmp_printf("Private Key (x): %Zd\n", sk->x);
    // gmp_printf("Public Key (y): %Zd\n", pk->y);
}

void test_sign_verify(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t r, s;

    mpz_inits(r, s, NULL);
    crypto_sign(r, s, m, m_len, &sk, &pp, sec_level);
    // gmp_printf("Signature (r): %Zd\n", r);
    // gmp_printf("Signature (s): %Zd\n", s);

    printf("[0] ElGamal Signature:\t");
    if (crypto_verify(r, s, m, m_len, &pk, &pp, sec_level))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(r, s, NULL);
}

int main()
{
    printf("\n===================== ELGAMAL SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    sec_level_t sec_level = L0;

    // Test ElGamal signature
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, &pp);
    test_sign_verify(sk, pk, pp, sec_level);

    return 0;
}