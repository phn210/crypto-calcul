#include "ecdh.h"

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

void test_keygen(mpz_t secret, mpz_t public, const public_params_t *pp)
{
    gen_secret(secret, pp);
    gen_public(public, secret, pp);

    // Print keys for debugging
    // gmp_printf("Secret Key: %Zd\n", secret);
    // gmp_printf("Public Key: %Zd\n", public);
}

void test_compute_shared_secret(mpz_t shared_secret, const mpz_t secret, const mpz_t public, const public_params_t *pp)
{
    compute_shared_secret(shared_secret, secret, public, pp);

    // Print shared secret for debugging
    // gmp_printf("Shared Secret: %Zd\n", shared_secret);
}

int main()
{
    printf("\n===================== ELLIPTIC CURVE DIFFIE-HELLMAN TEST =====================\n\n");

    public_params_t pp;
    mpz_t secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b;

    mpz_inits(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);

    // Test setup
    test_setup(&pp, WEIERSTRASS, P256K1);

    // Test key generation for party A
    test_keygen(secret_a, public_a, &pp);

    // Test key generation for party B
    test_keygen(secret_b, public_b, &pp);

    // Test compute shared secret for party A
    test_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp);

    // Test compute shared secret for party B
    test_compute_shared_secret(shared_secret_b, secret_b, public_a, &pp);

    // Verify that both shared secrets are equal
    printf("ECDH Key Exchange:\t");
    if (mpz_cmp(shared_secret_a, shared_secret_b) == 0)
    {
        printf("PASSED\n");
    }
    else
    {
        printf("FAILED\n");
    }

    mpz_clears(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);
    free_curve(&pp.curve);

    return 0;
}