#include "ecelgamal.h"

static int test_sign_verify(ec_t curve_type, unsigned char curve_id, hash_func_t hash_function, char *name, size_t name_len)
{
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    if (ecelgamal_setup(&pp, curve_type, curve_id) != CC_OK)
        return 0;
    snprintf(name, name_len, "%s", pp.curve.name);
    if (ecelgamal_keygen(&sk, &pk, &pp) != CC_OK)
    {
        ecelgamal_free_params(&pp);
        return 0;
    }

    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t s1, s2;
    mpz_inits(s1, s2, NULL);

    int passed = ecelgamal_sign(s1, s2, m, m_len, &sk, &pp, hash_function) == CC_OK &&
                 ecelgamal_verify(s1, s2, m, m_len, &pk, &pp, hash_function) == CC_OK &&
                 ecelgamal_verify(s1, s2, m, m_len - 1, &pk, &pp, hash_function) == CC_ERR_VERIFY;
    mpz_set_ui(s2, 0);
    passed &= ecelgamal_verify(s1, s2, m, m_len, &pk, &pp, hash_function) == CC_ERR_VERIFY;

    mpz_clears(s1, s2, NULL);
    ecelgamal_free_keys(&sk, &pk);
    ecelgamal_free_params(&pp);
    return passed;
}

int main()
{
    printf("\n===================== EC ELGAMAL SIGNATURE TEST =====================\n\n");

    char name[32];
    int passed = test_sign_verify(WEIERSTRASS, P256K1, SHA2, name, sizeof(name));
    printf("[0] EC ElGamal Signature, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");
    passed = test_sign_verify(EDWARDS, ED448, SHA3, name, sizeof(name));
    printf("[1] EC ElGamal Signature, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");

    // Montgomery curves have no point addition: reported instead of exiting
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    mpz_t s1, s2;
    mpz_inits(s1, s2, NULL);
    passed = 0;
    if (ecelgamal_setup(&pp, MONTGOMERY, C25519) == CC_OK)
    {
        if (ecelgamal_keygen(&sk, &pk, &pp) == CC_OK)
        {
            passed = ecelgamal_sign(s1, s2, (unsigned char *)"m", 1, &sk, &pp, SHA2) == CC_ERR_UNSUPPORTED;
            ecelgamal_free_keys(&sk, &pk);
        }
        ecelgamal_free_params(&pp);
    }
    printf("[2] Montgomery unsupported:\t%s\n", passed ? "PASSED" : "FAILED");
    mpz_clears(s1, s2, NULL);

    return 0;
}
