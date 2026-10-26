#include "ecelgamal.h"

static int test_encrypt_decrypt(ec_t curve_type, unsigned char curve_id, hash_func_t hash_function, char *name, size_t name_len)
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

    // Leading zero bytes must survive the round trip
    const unsigned char m[] = {0x00, 0x00, '1', '2', '3', '4', '5'};
    size_t c1_len = point_size(pp.curve);
    unsigned char *c1 = malloc(c1_len), c2[sizeof(m)], decrypted[sizeof(m)];

    int passed = ecelgamal_encrypt(c1, c2, m, sizeof(m), &pk, &pp, hash_function) == CC_OK &&
                 ecelgamal_decrypt(decrypted, c1, c1_len, c2, sizeof(c2), &sk, &pp, hash_function) == CC_OK &&
                 memcmp(m, decrypted, sizeof(m)) == 0;

    // Wrong C1 length, an invalid point and an oversized message are rejected
    unsigned char big[65];
    memset(big, 0xff, sizeof(big));
    passed &= ecelgamal_decrypt(decrypted, c1, c1_len - 1, c2, sizeof(c2), &sk, &pp, hash_function) == CC_ERR_INVALID_INPUT;
    memset(c1, 0xff, c1_len);
    passed &= ecelgamal_decrypt(decrypted, c1, c1_len, c2, sizeof(c2), &sk, &pp, hash_function) == CC_ERR_INVALID_INPUT;
    passed &= ecelgamal_encrypt(c1, big, big, pp.curve.md_len + 1, &pk, &pp, hash_function) == CC_ERR_MSG_TOO_LONG;

    free(c1);
    ecelgamal_free_keys(&sk, &pk);
    ecelgamal_free_params(&pp);
    return passed;
}

int main()
{
    printf("\n===================== EC ELGAMAL ENCRYPTION TEST =====================\n\n");

    char name[32];
    int passed = test_encrypt_decrypt(WEIERSTRASS, P256K1, SHA2, name, sizeof(name));
    printf("[0] EC-ElGamal, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");
    passed = test_encrypt_decrypt(MONTGOMERY, C25519, SHA3, name, sizeof(name));
    printf("[1] EC-ElGamal, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");
    passed = test_encrypt_decrypt(EDWARDS, ED25519, SHA2, name, sizeof(name));
    printf("[2] EC-ElGamal, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");
    passed = test_encrypt_decrypt(MONTGOMERY, C448, SHA2, name, sizeof(name));
    printf("[3] EC-ElGamal, %s:\t%s\n", name, passed ? "PASSED" : "FAILED");

    return 0;
}
