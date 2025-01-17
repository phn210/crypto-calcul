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

void test_sign_verify(priv_key_t sk, pub_key_t pk, public_params_t pp, hash_func_t hash_function)
{
    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t s1, s2;

    mpz_inits(s1, s2, NULL);
    crypto_sign(s1, s2, m, m_len, &sk, &pp, hash_function);
    // gmp_printf("Signature (s1): %Zd\n", s1);
    // gmp_printf("Signature (s2): %Zd\n", s2);

    printf("EC ElGamal Signature, %s:\t", pp.curve.name);
    if (crypto_verify(s1, s2, m, m_len, &pk, &pp, hash_function))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(s1, s2, sk.x, NULL);
    free_curve(&pp.curve);
    free_point(&pk.Y);
}

int main()
{
    printf("\n===================== EC ELGAMAL SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    // Test EC ElGamal Signature with P256K1 curve and SHA256 hash function
    printf("[0] ");
    test_setup(&pp, WEIERSTRASS, P256K1);
    test_keygen(&sk, &pk, &pp);
    test_sign_verify(sk, pk, pp, SHA2);

    // Test EC ElGamal Signature with ED448 curve and SHA3 hash function
    printf("[1] ");
    test_setup(&pp, EDWARDS, ED448);
    test_keygen(&sk, &pk, &pp);
    test_sign_verify(sk, pk, pp, SHA3);

    return 0;
}