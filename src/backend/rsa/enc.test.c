#include "rsa.h"
#include "conversion.h"

static const char *result(int passed)
{
    return passed ? "PASSED" : "FAILED";
}

static int test_textbook(const priv_key_t *sk, const pub_key_t *pk, rsa_algo_t algo)
{
    mpz_t m, c, decrypted_m;
    mpz_init_set_str(m, "1234567890", 10);
    mpz_inits(c, decrypted_m, NULL);

    int passed = rsa_encrypt(c, m, pk) == CC_OK &&
                 rsa_decrypt(decrypted_m, c, sk, algo) == CC_OK &&
                 mpz_cmp(m, decrypted_m) == 0;

    mpz_clears(m, c, decrypted_m, NULL);
    return passed;
}

typedef cc_status_t (*encrypt_fn)(unsigned char *, const unsigned char *, size_t, const pub_key_t *, sec_level_t);
typedef cc_status_t (*decrypt_fn)(unsigned char *, size_t *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t, sec_level_t);

static cc_status_t encrypt_pkcs1(unsigned char *c, const unsigned char *m, size_t m_len, const pub_key_t *pk, sec_level_t sec_level)
{
    UNUSED(sec_level);
    return rsa_encrypt_pkcs1(c, m, m_len, pk);
}

static cc_status_t decrypt_pkcs1(unsigned char *m, size_t *m_len, const unsigned char *c, size_t c_len, const priv_key_t *sk, rsa_algo_t algo, sec_level_t sec_level)
{
    UNUSED(sec_level);
    return rsa_decrypt_pkcs1(m, m_len, c, c_len, sk, algo);
}

// Round trip, including a message with leading zero bytes, plus rejection of a tampered ciphertext
static int test_padded(encrypt_fn encrypt, decrypt_fn decrypt, const priv_key_t *sk, const pub_key_t *pk, rsa_algo_t algo, sec_level_t sec_level)
{
    const unsigned char m[] = {0x00, 0x00, 'H', 'e', 'l', 'l', 'o'};
    size_t k = rsa_modulus_size(pk->n);
    unsigned char *c = malloc(k), *decrypted = malloc(k);
    size_t decrypted_len = 0;

    int passed = encrypt(c, m, sizeof(m), pk, sec_level) == CC_OK &&
                 decrypt(decrypted, &decrypted_len, c, k, sk, algo, sec_level) == CC_OK &&
                 decrypted_len == sizeof(m) && memcmp(m, decrypted, sizeof(m)) == 0;

    c[k / 2] ^= 0x01;
    passed &= decrypt(decrypted, &decrypted_len, c, k, sk, algo, sec_level) == CC_ERR_DECRYPT;
    passed &= decrypt(decrypted, &decrypted_len, c, k - 1, sk, algo, sec_level) == CC_ERR_DECRYPT;

    free(c);
    free(decrypted);
    return passed;
}

static int test_errors(const priv_key_t *sk, const pub_key_t *pk, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(pk->n);
    unsigned char *buf = calloc(k + 1, 1), *out = malloc(k);
    size_t out_len;
    mpz_t big, c;
    mpz_init_set(big, pk->n);
    mpz_init(c);

    int passed = rsa_encrypt(c, big, pk) == CC_ERR_MSG_TOO_LONG &&
                 rsa_decrypt(c, big, sk, RSA_STANDARD) == CC_ERR_INVALID_INPUT &&
                 rsa_decrypt(c, pk->e, sk, (rsa_algo_t)7) == CC_ERR_INVALID_ARG &&
                 rsa_encrypt_pkcs1(out, buf, k - 10, pk) == CC_ERR_MSG_TOO_LONG &&
                 rsa_encrypt_oaep(out, buf, k, pk, sec_level) == CC_ERR_MSG_TOO_LONG &&
                 rsa_encrypt_oaep(out, buf, 1, pk, (sec_level_t)1) == CC_ERR_INVALID_ARG;

    // A ciphertext >= n, and an all-zero ciphertext, are rejected without reading out of bounds
    memset(buf, 0xff, k);
    passed &= rsa_decrypt_pkcs1(out, &out_len, buf, k, sk, RSA_CRT) == CC_ERR_DECRYPT;
    passed &= rsa_decrypt_oaep(out, &out_len, buf, k, sk, RSA_CRT, sec_level) == CC_ERR_DECRYPT;
    memset(buf, 0x00, k);
    passed &= rsa_decrypt_pkcs1(out, &out_len, buf, k, sk, RSA_CRT) == CC_ERR_DECRYPT;
    passed &= rsa_decrypt_oaep(out, &out_len, buf, k, sk, RSA_CRT, sec_level) == CC_ERR_DECRYPT;

    mpz_clears(big, c, NULL);
    free(buf);
    free(out);
    return passed;
}

int main()
{
    printf("\n===================== RSA TEST =====================\n\n");

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
    printf("[2] PKCS#1 v1.5:\t\t%s\n", result(test_padded(encrypt_pkcs1, decrypt_pkcs1, &sk, &pk, RSA_STANDARD, sec_level)));
    printf("[3] PKCS#1 v1.5 mode CRT:\t%s\n", result(test_padded(encrypt_pkcs1, decrypt_pkcs1, &sk, &pk, RSA_CRT, sec_level)));
    printf("[4] OAEP:\t\t\t%s\n", result(test_padded(rsa_encrypt_oaep, rsa_decrypt_oaep, &sk, &pk, RSA_STANDARD, sec_level)));
    printf("[5] OAEP mode CRT:\t\t%s\n", result(test_padded(rsa_encrypt_oaep, rsa_decrypt_oaep, &sk, &pk, RSA_CRT, sec_level)));
    printf("[6] Errors:\t\t\t%s\n", result(test_errors(&sk, &pk, sec_level)));

    printf("[7] Modulus size:\t\t%s\n", result(mpz_sizeinbase(pk.n, 2) == (size_t)pp.n_bits));

    public_params_t bad_pp;
    printf("[8] Invalid level:\t\t%s\n", result(rsa_setup(&bad_pp, (sec_level_t)1) == CC_ERR_INVALID_ARG));

    rsa_free_keys(&sk, &pk);
    rsa_free_params(&pp);
    return 0;
}
