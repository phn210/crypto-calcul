#include "rsa.h"

void test_setup(public_params_t *pp, sec_level_t level)
{
    setup(pp, level);
    // gmp_printf("Public Parameters (n_bits): %d\n", pp->n_bits);
    // gmp_printf("Public Parameters (e): %Zd\n", pp->e);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp)
{
    keygen(sk, pk, pp);

    // gmp_printf("Private Key (p): %Zd\n", sk->p);
    // gmp_printf("Private Key (q): %Zd\n", sk->q);
    // gmp_printf("Private Key (d): %Zd\n", sk->d);
    // gmp_printf("Private Key (dp): %Zd\n", sk->dp);
    // gmp_printf("Private Key (dq): %Zd\n", sk->dq);
    // gmp_printf("Private Key (q_inv): %Zd\n", sk->q_inv);
    // gmp_printf("Public Key (n): %Zd\n", pk->n);
    // gmp_printf("Public Key (e): %Zd\n", pk->e);
}

void test_sign_verify(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign(s, m, &sk, RSA_STANDARD);
    // gmp_printf("Signature: %Zd\n", s);

    printf("[0] Textbook RSA:\t\t");
    if (crypto_verify(m, s, &pk))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_crt(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign(s, m, &sk, RSA_CRT);
    // gmp_printf("Signature: %Zd\n", s);

    printf("[1] Textbook RSA mode CRT:");
    if (crypto_verify(m, s, &pk))
        printf("\tPASSED\n");
    else
        printf("\tFAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_pkcs1(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign_pkcs1(s, m, &sk, RSA_STANDARD, sec_level);

    printf("[2] PKCS#1 v1.5:\t\t");
    if (crypto_verify_pkcs1(m, s, &pk, sec_level))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_pkcs1_crt(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign_pkcs1(s, m, &sk, RSA_CRT, sec_level);

    printf("[3] PKCS#1 v1.5 mode CRT:");
    if (crypto_verify_pkcs1(m, s, &pk, sec_level))
        printf("\tPASSED\n");
    else
        printf("\tFAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_pss(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign_pss(s, m, &sk, RSA_STANDARD, sec_level);

    printf("[4] PSS:\t\t\t");
    if (crypto_verify_pss(m, s, &pk, sec_level))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

void test_sign_verify_pss_crt(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, s;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    crypto_sign_pss(s, m, &sk, RSA_CRT, sec_level);

    printf("[5] PSS mode CRT:\t\t");
    if (crypto_verify_pss(m, s, &pk, sec_level))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, s, NULL);
}

int main()
{
    printf("\n===================== RSA SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    sec_level_t sec_level = L0;

    // Test standard RSA signature
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify(sk, pk, pp);

    // Test RSA signature with CRT optimization
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify_crt(sk, pk, pp);

    // Test PKCS#1 v1.5 signature
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify_pkcs1(sk, pk, pp, sec_level);

    // Test PKCS#1 v1.5 signature with CRT optimization
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify_pkcs1_crt(sk, pk, pp, sec_level);

    // Test PSS signature
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify_pss(sk, pk, pp, sec_level);

    // Test PSS signature with CRT optimization
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_sign_verify_pss_crt(sk, pk, pp, sec_level);

    return 0;
}