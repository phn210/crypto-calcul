#include "dh.h"
#include "test_util.h"

int main()
{
    printf("\n===================== DIFFIE-HELLMAN TEST =====================\n\n");

    public_params_t pp;
    mpz_t secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b;
    mpz_inits(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);

    EXPECT_OK(elgamal_setup(&pp, L0));
    EXPECT_OK(dh_gen_secret(secret_a, &pp));
    EXPECT_OK(dh_gen_public(public_a, secret_a, &pp));
    EXPECT_OK(dh_gen_secret(secret_b, &pp));
    EXPECT_OK(dh_gen_public(public_b, secret_b, &pp));
    EXPECT_OK(dh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp));
    EXPECT_OK(dh_compute_shared_secret(shared_secret_b, secret_b, public_a, &pp));

    printf("DH Key Exchange:\t%s\n", mpz_cmp(shared_secret_a, shared_secret_b) == 0 ? "PASSED" : "FAILED");

    // Peer values 1 and p - 1 would force the shared secret into {1, p - 1}
    mpz_set_ui(public_b, 1);
    int passed = dh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp) == CC_ERR_INVALID_INPUT;
    mpz_sub_ui(public_b, pp.p, 1);
    passed &= dh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp) == CC_ERR_INVALID_INPUT;
    printf("DH Errors:\t\t%s\n", passed ? "PASSED" : "FAILED");

    mpz_clears(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);
    elgamal_free_params(&pp);
    return 0;
}
