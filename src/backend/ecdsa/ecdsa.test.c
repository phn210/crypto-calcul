#include "ecdsa.h"

static int test_sign_verify(ec_t curve_type, unsigned char curve_id, hash_func_t hash_function, char *name, size_t name_len)
{
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    if (ecdsa_setup(&pp, curve_type, curve_id) != CC_OK)
        return 0;
    snprintf(name, name_len, "%s", pp.curve.name);
    if (ecdsa_keygen(&sk, &pk, &pp) != CC_OK)
    {
        ecdsa_free_params(&pp);
        return 0;
    }

    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t r, s;
    mpz_inits(r, s, NULL);

    int passed = ecdsa_sign(r, s, m, m_len, &sk, &pp, hash_function) == CC_OK &&
                 ecdsa_verify(r, s, m, m_len, &pk, &pp, hash_function) == CC_OK &&
                 ecdsa_verify(r, s, m, m_len - 1, &pk, &pp, hash_function) == CC_ERR_VERIFY;
    mpz_set_ui(s, 0);
    passed &= ecdsa_verify(r, s, m, m_len, &pk, &pp, hash_function) == CC_ERR_VERIFY;

    mpz_clears(r, s, NULL);
    ecdsa_free_keys(&sk, &pk);
    ecdsa_free_params(&pp);
    return passed;
}

int main()
{
    printf("\n===================== ECDSA TEST =====================\n\n");

    char name[32];
    int passed = test_sign_verify(WEIERSTRASS, P256K1, SHA2, name, sizeof(name));
    printf("[0] ECDSA, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");
    passed = test_sign_verify(EDWARDS, ED448, SHA3, name, sizeof(name));
    printf("[1] ECDSA, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");

    public_params_t pp;
    passed = 0;
    if (ecdsa_setup(&pp, MONTGOMERY, C25519) == CC_OK)
    {
        mpz_t r, s;
        mpz_inits(r, s, NULL);
        mpz_set_ui(r, 1);
        mpz_set_ui(s, 1);
        priv_key_t sk;
        pub_key_t pk;
        if (ecdsa_keygen(&sk, &pk, &pp) == CC_OK)
        {
            passed = ecdsa_sign(r, s, (unsigned char *)"m", 1, &sk, &pp, SHA2) == CC_ERR_UNSUPPORTED &&
                     ecdsa_verify(r, s, (unsigned char *)"m", 1, &pk, &pp, SHA2) == CC_ERR_UNSUPPORTED;
            ecdsa_free_keys(&sk, &pk);
        }
        mpz_clears(r, s, NULL);
        ecdsa_free_params(&pp);
    }
    passed &= ecdsa_setup(&pp, WEIERSTRASS, 42) == CC_ERR_INVALID_ARG;
    printf("[2] Errors:\t\t%s\n", passed ? "PASSED" : "FAILED");
    return 0;
}
