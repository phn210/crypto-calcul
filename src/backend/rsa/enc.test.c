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

    // gmp_printf("Private Key (n): %Zd\n", sk->n);
    // gmp_printf("Private Key (p): %Zd\n", sk->p);
    // gmp_printf("Private Key (q): %Zd\n", sk->q);
    // gmp_printf("Private Key (d): %Zd\n", sk->d);
    // gmp_printf("Private Key (dp): %Zd\n", sk->dp);
    // gmp_printf("Private Key (dq): %Zd\n", sk->dq);
    // gmp_printf("Private Key (q_inv): %Zd\n", sk->q_inv);
    // gmp_printf("Public Key (n): %Zd\n", pk->n);
    // gmp_printf("Public Key (e): %Zd\n", pk->e);
}

void test_encrypt_decrypt(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt(c, m, &pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    crypto_decrypt(decrypted_m, c, &sk, RSA_STANDARD);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("[0] Textbook RSA:\t\t");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_crt(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt(c, m, &pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    crypto_decrypt(decrypted_m, c, &sk, RSA_CRT);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("[1] Textbook RSA mode CRT:");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("\tPASSED\n");
    else
        printf("\tFAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_pkcs1(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt_pkcs1(c, m, &pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    crypto_decrypt_pkcs1(decrypted_m, c, &sk, RSA_STANDARD);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("[2] PKCS#1 v1.5:\t\t");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_pkcs1_crt(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt_pkcs1(c, m, &pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    crypto_decrypt_pkcs1(decrypted_m, c, &sk, RSA_CRT);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("[3] PKCS#1 v1.5 mode CRT:");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("\tPASSED\n");
    else
        printf("\tFAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_oaep(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt_oaep(c, m, &pk, sec_level);
    crypto_decrypt_oaep(decrypted_m, c, &sk, RSA_STANDARD, sec_level);

    printf("[4] OAEP:\t\t\t");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_oaep_crt(priv_key_t sk, pub_key_t pk, public_params_t pp, sec_level_t sec_level)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    crypto_encrypt_oaep(c, m, &pk, sec_level);
    crypto_decrypt_oaep(decrypted_m, c, &sk, RSA_CRT, sec_level);

    printf("[5] OAEP mode CRT:\t\t");
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(pp.e, sk.n, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.q_inv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

int main()
{
    printf("\n===================== RSA TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    priv_key_t sk_crt;
    sec_level_t sec_level = L0;

    // Test standard RSA
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_encrypt_decrypt(sk, pk, pp);

    // Test RSA in CRT mode
    test_setup(&pp, sec_level);
    test_keygen(&sk_crt, &pk, pp);
    test_encrypt_decrypt_crt(sk_crt, pk, pp);

    // Test PKCS#1 v1.5
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_encrypt_decrypt_pkcs1(sk, pk, pp);

    // Test PKCS#1 v1.5 in CRT mode
    test_setup(&pp, sec_level);
    test_keygen(&sk_crt, &pk, pp);
    test_encrypt_decrypt_pkcs1_crt(sk_crt, pk, pp);

    // Test OAEP
    test_setup(&pp, sec_level);
    test_keygen(&sk, &pk, pp);
    test_encrypt_decrypt_oaep(sk, pk, pp, sec_level);

    // Test OAEP in CRT mode
    test_setup(&pp, sec_level);
    test_keygen(&sk_crt, &pk, pp);
    test_encrypt_decrypt_oaep_crt(sk_crt, pk, pp, sec_level);

    return 0;
}