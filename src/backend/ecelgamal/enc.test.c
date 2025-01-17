#include "ecelgamal.h"

void test_setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id)
{
    setup(pp, curve_type, curve_id);
    // Print parameters for debugging
    // gmp_printf("Curve Parameters (p): %Zd\n", pp->curve.p);
    // gmp_printf("Curve Parameters (a): %Zd\n", pp->curve.a);
    // gmp_printf("Curve Parameters (b): %Zd\n", pp->curve.b);
    // gmp_printf("Curve Parameters (Gx): %Zd\n", pp->curve.Gx);
    // gmp_printf("Curve Parameters (Gy): %Zd\n", pp->curve.Gy);
    // gmp_printf("Curve Parameters (n): %Zd\n", pp->curve.n);
}

void test_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    keygen(sk, pk, pp);

    // Print keys for debugging
    // gmp_printf("Private Key (x): %Zd\n", sk->x);
    // gmp_printf("Public Key (Yx): %Zd\n", pk->Y.x);
    // gmp_printf("Public Key (Yy): %Zd\n", pk->Y.y);
}

void test_encrypt_decrypt(priv_key_t sk, pub_key_t pk, public_params_t pp, hash_func_t hash_function)
{
    mpz_t m, c1, c2, decrypted_m;

    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c1, c2, decrypted_m, NULL);
    // gmp_printf("Message: %Zd\n", m);

    crypto_encrypt(c1, c2, m, &pk, &pp, hash_function);
    // gmp_printf("Ciphertext (c1): %Zd\n", c1);
    // gmp_printf("Ciphertext (c2): %Zd\n", c2);

    crypto_decrypt(decrypted_m, c1, c2, &sk, &pp, hash_function);
    // gmp_printf("Decrypted Message: %Zd\n", decrypted_m);

    printf("EC-ElGamal, %s:\t", pp.curve.name);
    if (mpz_cmp(m, decrypted_m) == 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(m, c1, c2, sk.x, decrypted_m, NULL);
    free_curve(&pp.curve);
    free_point(&pk.Y);
}

int main()
{
    printf("\n===================== EC ELGAMAL ENCRYPTION TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    // Test EC ElGamal encryption with secp256k1 curve
    printf("[0] ");
    test_setup(&pp, WEIERSTRASS, P256K1);
    test_keygen(&sk, &pk, &pp);
    test_encrypt_decrypt(sk, pk, pp, SHA2);

    // Test EC ElGamal encryption with Curve25519 curve
    printf("[1] ");
    test_setup(&pp, MONTGOMERY, C25519);
    test_keygen(&sk, &pk, &pp);
    test_encrypt_decrypt(sk, pk, pp, SHA3);

    // Test EC ElGamal encryption with Ed25519 curve
    printf("[2] ");
    test_setup(&pp, EDWARDS, ED25519);
    test_keygen(&sk, &pk, &pp);
    test_encrypt_decrypt(sk, pk, pp, SHA2);

    return 0;
}