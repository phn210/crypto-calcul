#include "elgamal.h"

int main()
{
    printf("\n===================== ELGAMAL TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;

    if (elgamal_setup(&pp, L0) != CC_OK || elgamal_keygen(&sk, &pk, &pp) != CC_OK)
    {
        printf("ElGamal key generation:\tFAILED\n");
        return 1;
    }

    mpz_t m, c1, c2, decrypted_m;
    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c1, c2, decrypted_m, NULL);

    int passed = elgamal_encrypt(c1, c2, m, &pk, &pp) == CC_OK &&
                 elgamal_decrypt(decrypted_m, c1, c2, &sk, &pp) == CC_OK &&
                 mpz_cmp(m, decrypted_m) == 0;
    printf("[0] Textbook ElGamal:\t%s\n", passed ? "PASSED" : "FAILED");

    // Messages >= p, out-of-range ciphertexts and unknown levels are rejected
    public_params_t bad_pp;
    passed = elgamal_encrypt(c1, c2, pp.p, &pk, &pp) == CC_ERR_MSG_TOO_LONG &&
             elgamal_decrypt(decrypted_m, pp.p, c2, &sk, &pp) == CC_ERR_INVALID_INPUT &&
             elgamal_setup(&bad_pp, L3) == CC_ERR_INVALID_ARG;
    mpz_set_ui(c1, 0);
    passed &= elgamal_decrypt(decrypted_m, c1, c2, &sk, &pp) == CC_ERR_INVALID_INPUT;
    printf("[1] Errors:\t\t%s\n", passed ? "PASSED" : "FAILED");

    mpz_clears(m, c1, c2, decrypted_m, NULL);
    elgamal_free_keys(&sk, &pk);
    elgamal_free_params(&pp);
    return 0;
}
