#include "dsa.h"

void test_setup(public_params_t *pp, sec_level_t level, hash_func_t hash)
{
    setup(pp, level, hash);

    // gmp_printf("Public Parameters (p): %Zd\n", pp->p);
    // gmp_printf("Public Parameters (q): %Zd\n", pp->q);
    // gmp_printf("Public Parameters (g): %Zd\n", pp->g);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp)
{
    keygen(sk, pk, pp);

    // gmp_printf("Private Key (x): %Zd\n", sk->x);
    // gmp_printf("Public Key (y): %Zd\n", pk->y);
}

void test_sign_verify(const priv_key_t sk, const pub_key_t pk, const public_params_t pp)
{
    mpz_t r, s, m;
    mpz_inits(r, s, m, NULL);

    const unsigned char message[12] = "Hello, DSA!";

    crypto_sign(r, s, message, 12, sk, pp);
    // gmp_printf("Signature (r): %Zd\n", r);
    // gmp_printf("Signature (s): %Zd\n", s);

    char valid = crypto_verify(r, s, message, 12, pk, pp);
    printf("DSA:\t%s", valid ? "PASSED\n" : "FAILED\n");
    mpz_clears(r, s, m, NULL);
}

int main()
{
    printf("\n===================== DSA TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    test_setup(&pp, L0, SHA3);
    test_keygen(&sk, &pk, pp);
    test_sign_verify(sk, pk, pp);

    mpz_clears(pp.p, pp.q, pp.g, sk.x, pk.y, NULL);

    return 0;
}