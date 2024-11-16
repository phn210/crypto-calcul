#include "elgamal.h"

void test_keygen(priv_key *sk, pub_key *pk)
{
    keygen(sk, pk);

    gmp_printf("Private Key: %Zd\n", sk->x);
    gmp_printf("Public Key (p): %Zd\n", pk->p);
    gmp_printf("Public Key (g): %Zd\n", pk->g);
    gmp_printf("Public Key (y): %Zd\n", pk->y);
}

void test_encrypt_decrypt(priv_key sk, pub_key pk)
{
    mpz_t m, c1, c2, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c1, c2, decrypted_m, NULL);

    encrypt(c1, c2, m, pk);
    gmp_printf("Ciphertext (c1): %Zd\n", c1);
    gmp_printf("Ciphertext (c2): %Zd\n", c2);

    decrypt(decrypted_m, c1, c2, sk, pk);
    gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    if (mpz_cmp(m, decrypted_m) == 0)
    {
        printf("Encryption and Decryption successful!\n");
    }
    else
    {
        printf("Encryption and Decryption failed!\n");
    }

    mpz_clears(sk.x, pk.p, pk.g, pk.y, m, c1, c2, decrypted_m, NULL);
}

int main()
{
    printf("\n===================== ELGAMAL TEST =====================\n\n");

    priv_key sk;
    pub_key pk;

    test_keygen(&sk, &pk);
    test_encrypt_decrypt(sk, pk);

    return 0;
}