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

void test_encrypt_decrypt(priv_key sk, pub_key pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    encrypt(c, m, pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    decrypt(decrypted_m, c, sk, pk);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    if (mpz_cmp(m, decrypted_m) == 0)
    {
        printf("Encryption and Decryption successful!\n");
    }
    else
    {
        printf("Encryption and Decryption failed!\n");
    }

    mpz_clears(pp.e, sk.p, sk.q, sk.d, pk.n, pk.e, m, c, decrypted_m, NULL);
}

void test_encrypt_decrypt_crt(priv_key_crt sk, pub_key pk, public_params_t pp)
{
    mpz_t m, c, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    encrypt_crt(c, m, pk);
    // gmp_printf("Ciphertext: %Zd\n", c);

    decrypt_crt(decrypted_m, c, sk, pk);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    if (mpz_cmp(m, decrypted_m) == 0)
    {
        printf("CRT Encryption and Decryption successful!\n");
    }
    else
    {
        printf("CRT Encryption and Decryption failed!\n");
    }

    mpz_clears(pp.e, sk.p, sk.q, sk.d, sk.dp, sk.dq, sk.qinv, pk.n, pk.e, m, c, decrypted_m, NULL);
}

int main()
{
    printf("\n===================== RSA TEST =====================\n\n");

    public_params_t pp;
    priv_key sk;
    pub_key pk;
    priv_key_crt sk_crt;

    // Test standard RSA
    test_setup(&pp, L0);
    test_keygen(&sk, &pk, pp);
    test_encrypt_decrypt(sk, pk, pp);

    // Test RSA with CRT optimization
    test_setup(&pp, L0);
    test_keygen_crt(&sk_crt, &pk, pp);
    test_encrypt_decrypt_crt(sk_crt, pk, pp);

    return 0;
}