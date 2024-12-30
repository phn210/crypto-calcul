#include "rsa.h"

void test_setup(public_params_t *pp, SECURITY_LEVEL level)
{
    setup(pp, level);
    // gmp_printf("Public Parameters (n_bits): %d\n", pp->n_bits);
    // gmp_printf("Public Parameters (e): %Zd\n", pp->e);
}

void test_keygen(priv_key *sk, pub_key *pk, const public_params_t pp)
{
    keygen(sk, pk, pp);

    // gmp_printf("Private Key (p): %Zd\n", sk->p);
    // gmp_printf("Private Key (q): %Zd\n", sk->q);
    // gmp_printf("Private Key (d): %Zd\n", sk->d);
    // gmp_printf("Public Key (n): %Zd\n", pk->n);
    // gmp_printf("Public Key (e): %Zd\n", pk->e);
}

void test_keygen_crt(priv_key_crt *sk, pub_key *pk, const public_params_t pp)
{
    keygen_crt(sk, pk, pp);

    // gmp_printf("Private Key (p): %Zd\n", sk->p);
    // gmp_printf("Private Key (q): %Zd\n", sk->q);
    // gmp_printf("Private Key (d): %Zd\n", sk->d);
    // gmp_printf("Private Key (dp): %Zd\n", sk->dp);
    // gmp_printf("Private Key (dq): %Zd\n", sk->dq);
    // gmp_printf("Private Key (qinv): %Zd\n", sk->qinv);
    // gmp_printf("Public Key (n): %Zd\n", pk->n);
    // gmp_printf("Public Key (e): %Zd\n", pk->e);
}

void test_sign_verify(priv_key sk, pub_key pk, public_params_t pp)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    sign(s, m, sk, pk);
    // gmp_printf("Signature: %Zd\n", s);

    if (verify(m, s, pk))
    {
        printf("Signature verification successful!\n");
    }
    else
    {
        printf("Signature verification failed!\n");
    }

    mpz_clears(pp.e, sk.p, sk.q, sk.d, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_crt(priv_key_crt sk, pub_key pk, public_params_t pp)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    sign_crt(s, m, sk, pk);
    // gmp_printf("Signature: %Zd\n", s);

    if (verify(m, s, pk))
    {
        printf("CRT Signature verification successful!\n");
    }
    else
    {
        printf("CRT Signature verification failed!\n");
    }

    mpz_clears(pp.e, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.qinv, pk.n, pk.e, m, s, NULL);
}

int main()
{
    printf("\n===================== RSA SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key sk;
    pub_key pk;
    priv_key_crt sk_crt;

    // Test standard RSA signature
    test_setup(&pp, L0);
    test_keygen(&sk, &pk, pp);
    test_sign_verify(sk, pk, pp);

    // Test RSA signature with CRT optimization
    test_setup(&pp, L0);
    test_keygen_crt(&sk_crt, &pk, pp);
    test_sign_verify_crt(sk_crt, pk, pp);

    return 0;
}