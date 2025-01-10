#include "dh.h"

void test_setup(public_params_t *pp, sec_level_t level)
{
    setup(pp, level);
    // Print parameters for debugging
    // gmp_printf("Public Parameters (p): %Zd\n", pp->p);
    // gmp_printf("Public Parameters (g): %Zd\n", pp->g);
}

void test_keygen(mpz_t secret, mpz_t public, const public_params_t *pp)
{
    gen_secret(secret, *pp);
    gen_public(public, secret, *pp);

    // Print keys for debugging
    // gmp_printf("Secret Key: %Zd\n", secret);
    // gmp_printf("Public Key: %Zd\n", public);
}

void test_compute_shared_secret(mpz_t shared_secret, const mpz_t secret, const mpz_t public, const public_params_t *pp)
{
    compute_shared_secret(shared_secret, secret, public, *pp);

    // Print shared secret for debugging
    // gmp_printf("Shared Secret: %Zd\n", shared_secret);
}

int main()
{
    printf("\n===================== DIFFIE-HELLMAN TEST =====================\n\n");

    public_params_t pp;
    mpz_t secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b;

    mpz_inits(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);

    // Test setup
    test_setup(&pp, L0);

    // Test key generation for party A
    test_keygen(secret_a, public_a, &pp);

    // Test key generation for party B
    test_keygen(secret_b, public_b, &pp);

    // Test compute shared secret for party A
    test_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp);

    // Test compute shared secret for party B
    test_compute_shared_secret(shared_secret_b, secret_b, public_a, &pp);

    // Verify that both shared secrets are equal
    printf("DH Key Exchange:\t");
    if (mpz_cmp(shared_secret_a, shared_secret_b) == 0)
    {
        printf("PASSED\n");
    }
    else
    {
        printf("FAILED\n");
    }

    mpz_clears(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);
    mpz_clears(pp.p, pp.g, NULL);

    return 0;
}