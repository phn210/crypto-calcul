#include "elgamal.h"

void test_setup(public_params_t *pp, sec_level_t level)
{
    setup(pp, level);

    // gmp_printf("Public Parameters (p): %Zd\n", pp->p);
    // gmp_printf("Public Parameters (g): %Zd\n", pp->g);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp)
{
    keygen(sk, pk, &pp);

    // gmp_printf("Private Key: %Zd\n", sk->x);
    // gmp_printf("Public Key (y): %Zd\n", pk->y);
}

void test_encrypt_decrypt(priv_key_t sk, pub_key_t pk, public_params_t pp)
{
    mpz_t m, c1, c2, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c1, c2, decrypted_m, NULL);

    crypto_encrypt(c1, c2, m, &pk, &pp);
    // gmp_printf("Ciphertext (c1): %Zd\n", c1);
    // gmp_printf("Ciphertext (c2): %Zd\n", c2);

    crypto_decrypt(decrypted_m, c1, c2, &sk, &pp);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("[0] Textbook ElGamal:\t");
    if (mpz_cmp(m, decrypted_m) == 0)
    {
        printf("PASSED\n");
    }
    else
    {
        printf("FAILED\n");
    }

    mpz_clears(pp.p, pp.g, sk.x, pk.y, m, c1, c2, decrypted_m, NULL);
}

int main()
{
    printf("\n===================== ELGAMAL TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    test_setup(&pp, L0);
    test_keygen(&sk, &pk, pp);
    test_encrypt_decrypt(sk, pk, pp);

    return 0;
}