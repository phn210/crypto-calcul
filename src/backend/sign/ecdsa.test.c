#include "ecdsa.h"

void test_setup(public_params_t *pp, SECURITY_LEVEL level, EC curve_type, unsigned char curve_id)
{
    setup(pp, level, curve_type, curve_id);
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
    // gmp_printf("Private Key (d): %Zd\n", sk->d);
    // gmp_printf("Public Key (Qx): %Zd\n", pk->Q.x);
    // gmp_printf("Public Key (Qy): %Zd\n", pk->Q.y);
}

void test_sign_verify(priv_key_t sk, pub_key_t pk, public_params_t pp, HASH_FUNCTION hash_function)
{
    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t r, s;

    mpz_inits(r, s, NULL);
    sign(r, s, m, m_len, &sk, &pp, hash_function);
    // gmp_printf("Signature (r): %Zd\n", r);
    // gmp_printf("Signature (s): %Zd\n", s);

    printf("[0] ECDSA, %s:\t", pp.curve.name);
    if (verify(r, s, m, m_len, &pk, &pp, hash_function))
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(r, s, NULL);
    free_curve(&pp.curve);
}

int main()
{
    printf("\n===================== ECDSA TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    // Test ECDSA with P256K1 curve and SHA256 hash function
    test_setup(&pp, L1, WEIERSTRASS, P256K1);
    test_keygen(&sk, &pk, &pp);
    test_sign_verify(sk, pk, pp, SHA2);

    // Test ECDSA with ED448 curve and SHA3 hash function
    test_setup(&pp, L2, EDWARDS, ED448);
    test_keygen(&sk, &pk, &pp);
    test_sign_verify(sk, pk, pp, SHA3);

    return 0;
}