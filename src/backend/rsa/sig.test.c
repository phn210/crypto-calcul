#include "rsa.h"

static const char *result(int passed)
{
    return passed ? "PASSED" : "FAILED";
}

static int test_textbook(const priv_key_t *sk, const pub_key_t *pk, rsa_algo_t algo)
{
    mpz_t m, s;
    mpz_init_set_str(m, "1234567890", 10);
    mpz_init(s);

    int passed = rsa_sign(s, m, sk, algo) == CC_OK && rsa_verify(m, s, pk) == CC_OK;
    mpz_add_ui(m, m, 1);
    passed &= rsa_verify(m, s, pk) == CC_ERR_VERIFY;

    mpz_clears(m, s, NULL);
    return passed;
}

typedef cc_status_t (*sign_fn)(unsigned char *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t, sec_level_t);
typedef cc_status_t (*verify_fn)(const unsigned char *, size_t, const unsigned char *, size_t, const pub_key_t *, sec_level_t);

// Many signatures, so that encoded messages with a leading zero byte are covered (about 1 in 128 for PSS)
static int test_padded(sign_fn sign, verify_fn verify, const priv_key_t *sk, const pub_key_t *pk, rsa_algo_t algo, sec_level_t sec_level, int rounds)
{
    unsigned char m[] = {0x00, 'H', 'e', 'l', 'l', 'o', 0};
    size_t k = rsa_modulus_size(pk->n);
    unsigned char *s = malloc(k);
    int passed = 1;

    for (int i = 0; i < rounds && passed; i++)
    {
        m[sizeof(m) - 1] = (unsigned char)i;
        passed = sign(s, m, sizeof(m), sk, algo, sec_level) == CC_OK &&
                 verify(m, sizeof(m), s, k, pk, sec_level) == CC_OK;
    }

    // Tampered message, tampered signature and truncated signature
    m[1] ^= 0x01;
    passed &= verify(m, sizeof(m), s, k, pk, sec_level) == CC_ERR_VERIFY;
    m[1] ^= 0x01;
    s[k / 2] ^= 0x01;
    passed &= verify(m, sizeof(m), s, k, pk, sec_level) == CC_ERR_VERIFY;
    passed &= verify(m, sizeof(m), s, k - 1, pk, sec_level) == CC_ERR_VERIFY;
    memset(s, 0xff, k);
    passed &= verify(m, sizeof(m), s, k, pk, sec_level) == CC_ERR_VERIFY;

    free(s);
    return passed;
}

int main()
{
    printf("\n===================== RSA SIGNATURE TEST =====================\n\n");

    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    sec_level_t sec_level = L0;

    if (rsa_setup(&pp, sec_level) != CC_OK || rsa_keygen(&sk, &pk, &pp) != CC_OK)
    {
        printf("RSA key generation:\tFAILED\n");
        return 1;
    }

    printf("[0] Textbook RSA:\t\t%s\n", result(test_textbook(&sk, &pk, RSA_STANDARD)));
    printf("[1] Textbook RSA mode CRT:\t%s\n", result(test_textbook(&sk, &pk, RSA_CRT)));
    printf("[2] PKCS#1 v1.5:\t\t%s\n", result(test_padded(rsa_sign_pkcs1, rsa_verify_pkcs1, &sk, &pk, RSA_STANDARD, sec_level, 4)));
    printf("[3] PKCS#1 v1.5 mode CRT:\t%s\n", result(test_padded(rsa_sign_pkcs1, rsa_verify_pkcs1, &sk, &pk, RSA_CRT, sec_level, 4)));
    printf("[4] PSS:\t\t\t%s\n", result(test_padded(rsa_sign_pss, rsa_verify_pss, &sk, &pk, RSA_STANDARD, sec_level, 4)));
    printf("[5] PSS mode CRT:\t\t%s\n", result(test_padded(rsa_sign_pss, rsa_verify_pss, &sk, &pk, RSA_CRT, sec_level, 400)));

    rsa_free_keys(&sk, &pk);
    rsa_free_params(&pp);
    return 0;
}
