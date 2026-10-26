#include "ecdh.h"
#include "test_util.h"

static int test_exchange(ec_t curve_type, unsigned char curve_id)
{
    public_params_t pp;
    if (ecelgamal_setup(&pp, curve_type, curve_id) != CC_OK)
        return 0;

    mpz_t secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b;
    mpz_inits(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);

    int passed = ecdh_gen_secret(secret_a, &pp) == CC_OK &&
                 ecdh_gen_public(public_a, secret_a, &pp) == CC_OK &&
                 ecdh_gen_secret(secret_b, &pp) == CC_OK &&
                 ecdh_gen_public(public_b, secret_b, &pp) == CC_OK &&
                 ecdh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp) == CC_OK &&
                 ecdh_compute_shared_secret(shared_secret_b, secret_b, public_a, &pp) == CC_OK &&
                 mpz_cmp(shared_secret_a, shared_secret_b) == 0;

    // Peer values that are too large or not on the curve are rejected
    mpz_mul_2exp(public_b, public_b, 8 * point_size(pp.curve));
    passed &= ecdh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp) == CC_ERR_INVALID_INPUT;
    // All-ones encoding has coordinates >= p, invalid on every curve type
    mpz_set_ui(public_b, 1);
    mpz_mul_2exp(public_b, public_b, 8 * point_size(pp.curve));
    mpz_sub_ui(public_b, public_b, 1);
    passed &= ecdh_compute_shared_secret(shared_secret_a, secret_a, public_b, &pp) == CC_ERR_INVALID_INPUT;

    mpz_clears(secret_a, public_a, secret_b, public_b, shared_secret_a, shared_secret_b, NULL);
    ecelgamal_free_params(&pp);
    return passed;
}

int main()
{
    printf("\n===================== ELLIPTIC CURVE DIFFIE-HELLMAN TEST =====================\n\n");

    printf("ECDH Key Exchange:\t%s\n", test_exchange(WEIERSTRASS, P256K1) ? "PASSED" : "FAILED");
    printf("ECDH Curve25519:\t%s\n", test_exchange(MONTGOMERY, C25519) ? "PASSED" : "FAILED");
    printf("ECDH Edwards448:\t%s\n", test_exchange(EDWARDS, ED448) ? "PASSED" : "FAILED");
    return 0;
}
