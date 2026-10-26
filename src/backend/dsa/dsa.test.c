#include "dsa.h"

static int test_sign_verify(sec_level_t level, hash_func_t hash)
{
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    if (dsa_setup(&pp, level, hash) != CC_OK)
        return 0;
    if (dsa_keygen(&sk, &pk, &pp) != CC_OK)
    {
        dsa_free_params(&pp);
        return 0;
    }

    mpz_t r, s;
    mpz_inits(r, s, NULL);
    const unsigned char message[12] = "Hello, DSA!";

    int passed = dsa_sign(r, s, message, sizeof(message), &sk, &pp) == CC_OK &&
                 dsa_verify(r, s, message, sizeof(message), &pk, &pp) == CC_OK &&
                 dsa_verify(r, s, message, sizeof(message) - 1, &pk, &pp) == CC_ERR_VERIFY;
    mpz_set_ui(s, 0);
    passed &= dsa_verify(r, s, message, sizeof(message), &pk, &pp) == CC_ERR_VERIFY;

    mpz_clears(r, s, NULL);
    dsa_free_keys(&sk, &pk);
    dsa_free_params(&pp);
    return passed;
}

int main()
{
    printf("\n===================== DSA TEST =====================\n\n");

    public_params_t pp;
    int passed = test_sign_verify(L0, SHA3) && test_sign_verify(L1, SHA2);
    printf("DSA:\t\t%s\n", passed ? "PASSED" : "FAILED");

    passed = dsa_setup(&pp, L2, SHA2) == CC_ERR_INVALID_ARG && dsa_setup(&pp, L0, MD5) == CC_ERR_INVALID_ARG;
    printf("DSA Errors:\t%s\n", passed ? "PASSED" : "FAILED");
    return 0;
}
