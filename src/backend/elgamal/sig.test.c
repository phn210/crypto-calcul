#include "elgamal.h"

int main()
{
    printf("\n===================== ELGAMAL SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    sec_level_t sec_level = L0;

    if (elgamal_setup(&pp, sec_level) != CC_OK || elgamal_keygen(&sk, &pk, &pp) != CC_OK)
    {
        printf("ElGamal key generation:\tFAILED\n");
        return 1;
    }

    const unsigned char *m = (unsigned char *)"1234567890";
    size_t m_len = strlen((const char *)m);
    mpz_t r, s;
    mpz_inits(r, s, NULL);

    int passed = elgamal_sign(r, s, m, m_len, &sk, &pp, sec_level) == CC_OK &&
                 elgamal_verify(r, s, m, m_len, &pk, &pp, sec_level) == CC_OK &&
                 elgamal_verify(r, s, m, m_len - 1, &pk, &pp, sec_level) == CC_ERR_VERIFY;
    printf("[0] ElGamal Signature:\t%s\n", passed ? "PASSED" : "FAILED");

    // r outside (0, p) is rejected
    mpz_set_ui(r, 0);
    passed = elgamal_verify(r, s, m, m_len, &pk, &pp, sec_level) == CC_ERR_VERIFY &&
             elgamal_sign(r, s, m, m_len, &sk, &pp, L3) == CC_ERR_INVALID_ARG;
    printf("[1] Errors:\t\t%s\n", passed ? "PASSED" : "FAILED");

    mpz_clears(r, s, NULL);
    elgamal_free_keys(&sk, &pk);
    elgamal_free_params(&pp);
    return 0;
}
