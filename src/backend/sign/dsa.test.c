#include <string.h>
#include "dsa.h"

void test_setup(public_params_t *pp, SECURITY_LEVEL level, HASH_FUNCTION hash)
{
    setup(pp, level, hash);

    gmp_printf("Public Parameters (p): %Zd\n", pp->p);
    gmp_printf("Public Parameters (q): %Zd\n", pp->q);
    gmp_printf("Public Parameters (g): %Zd\n", pp->g);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp)
{
    keygen(sk, pk, pp);

    gmp_printf("Private Key (x): %Zd\n", sk->x);
    gmp_printf("Public Key (y): %Zd\n", pk->y);
}

void test_sign_verify(const priv_key_t sk, const pub_key_t pk, const public_params_t pp)
{
    mpz_t r, s, m;
    mpz_inits(r, s, m, NULL);

    const unsigned char *message = "Hello, DSA!";

    sign(r, s, message, strlen(message), sk, pp);
    gmp_printf("Signature (r): %Zd\n", r);
    gmp_printf("Signature (s): %Zd\n", s);

    char valid = verify(r, s, message, strlen(message), pk, pp);
    if (valid)
    {
        printf("Signature is valid!\n");
    }
    else
    {
        printf("Signature is invalid!\n");
    }

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