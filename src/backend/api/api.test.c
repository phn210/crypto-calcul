// Tests the public API through the shared library only: no internal headers
#include "cryptocalc.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(name, cond)                                         \
    do                                                            \
    {                                                             \
        int ok_ = (cond);                                         \
        printf("%-48s%s\n", name, ok_ ? "PASSED" : "FAILED");     \
        failures += !ok_;                                         \
    } while (0)

static size_t from_hex(uint8_t *out, const char *hex)
{
    size_t len = strlen(hex) / 2;
    for (size_t i = 0; i < len; i++)
    {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
    return len;
}

static int equals_hex(const uint8_t *data, size_t len, const char *hex)
{
    uint8_t expected[128];
    return len == from_hex(expected, hex) && memcmp(data, expected, len) == 0;
}

static const uint8_t MSG[] = "Hello, crypto-calcul!";
#define MSG_LEN (sizeof(MSG) - 1)

static void test_status(void)
{
    int ok = 1;
    for (int s = CC_OK; s <= CC_ERR_NO_KEY; s++)
        ok &= cc_strerror((cc_status_t)s) != NULL && strcmp(cc_strerror((cc_status_t)s), "Unknown error") != 0;
    CHECK("cc_strerror covers every status", ok && strcmp(cc_strerror((cc_status_t)999), "Unknown error") == 0);
}

static void test_hash(void)
{
    uint8_t md[64];
    size_t len = sizeof(md);
    const uint8_t *abc = (const uint8_t *)"abc";

    CHECK("MD5(\"abc\")", cc_hash(CC_HASH_MD5, CC_SEC_128, abc, 3, md, &len) == CC_OK &&
                              equals_hex(md, len, "900150983cd24fb0d6963f7d28e17f72"));
    len = sizeof(md);
    CHECK("SHA-1(\"abc\")", cc_hash(CC_HASH_SHA1, CC_SEC_128, abc, 3, md, &len) == CC_OK &&
                                equals_hex(md, len, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    len = sizeof(md);
    CHECK("SHA-256(\"abc\")", cc_hash(CC_HASH_SHA2, CC_SEC_128, abc, 3, md, &len) == CC_OK &&
                                  equals_hex(md, len, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    len = sizeof(md);
    CHECK("SHA3-256(\"abc\")", cc_hash(CC_HASH_SHA3, CC_SEC_128, abc, 3, md, &len) == CC_OK &&
                                   equals_hex(md, len, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    CHECK("SHAKE128(\"\", 32)", cc_shake(128, NULL, 0, md, 32) == CC_OK &&
                                    equals_hex(md, 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));

    // Size query, short buffer and invalid parameters
    len = 0;
    int ok = cc_hash(CC_HASH_SHA2, CC_SEC_256, abc, 3, NULL, &len) == CC_ERR_BUFFER_TOO_SMALL && len == 64;
    len = 10;
    ok &= cc_hash(CC_HASH_SHA2, CC_SEC_256, abc, 3, md, &len) == CC_ERR_BUFFER_TOO_SMALL && len == 64;
    ok &= cc_hash((cc_hash_t)9, CC_SEC_128, abc, 3, md, &len) == CC_ERR_INVALID_ARG;
    ok &= cc_hash(CC_HASH_SHA2, (cc_sec_level_t)100, abc, 3, md, &len) == CC_ERR_INVALID_ARG;
    ok &= cc_shake(512, abc, 3, md, 32) == CC_ERR_INVALID_ARG;
    CHECK("Hash buffer negotiation and errors", ok);
}

static void test_random_and_primes(void)
{
    uint8_t out[512], m[] = {0x01, 0x00};
    size_t len = sizeof(out);
    int is_prime = 0;

    int ok = cc_random_bytes(out, 32) == CC_OK;
    ok &= cc_random_bits(16, out, &len) == CC_OK && len <= 2;
    len = sizeof(out);
    ok &= cc_random_below(m, sizeof(m), out, &len) == CC_OK && len == 1;
    len = sizeof(out);
    ok &= cc_random_below((const uint8_t *)"\0", 1, out, &len) == CC_ERR_INVALID_ARG;
    CHECK("Random numbers", ok);

    uint8_t mersenne[] = {0x7f, 0xff, 0xff, 0xff}; // 2^31 - 1
    uint8_t composite[] = {0x7f, 0xff, 0xff, 0xfd};
    uint8_t three[] = {3};
    ok = cc_is_prime(mersenne, sizeof(mersenne), CC_PRIME_TEST_MILLER_RABIN, 20, &is_prime) == CC_OK && is_prime;
    ok &= cc_is_prime(composite, sizeof(composite), CC_PRIME_TEST_FERMAT, 20, &is_prime) == CC_OK && !is_prime;
    ok &= cc_is_prime(three, 1, CC_PRIME_TEST_FERMAT, 20, &is_prime) == CC_OK && is_prime;
    ok &= cc_is_prime(three, 1, (cc_prime_test_t)7, 20, &is_prime) == CC_ERR_INVALID_ARG;
    CHECK("Primality tests", ok);

    len = sizeof(out);
    ok = cc_prime_bits(256, 100, CC_PRIME_TEST_MILLER_RABIN, 25, out, &len) == CC_OK && len == 32 && (out[0] & 0x80) &&
         cc_is_prime(out, len, CC_PRIME_TEST_GMP, 25, &is_prime) == CC_OK && is_prime;
    len = sizeof(out);
    ok &= cc_prime_below(mersenne, sizeof(mersenne), 100, CC_PRIME_TEST_MILLER_RABIN, 25, out, &len) == CC_OK &&
          len <= 4 && cc_is_prime(out, len, CC_PRIME_TEST_GMP, 25, &is_prime) == CC_OK && is_prime;
    len = sizeof(out);
    ok &= cc_prime_below(three, 0, 100, CC_PRIME_TEST_MILLER_RABIN, 25, out, &len) == CC_ERR_INVALID_ARG;
    CHECK("Prime generation", ok);
}

static void test_aes(void)
{
    // FIPS-197 C.1: the first ciphertext block, followed by a full padding block
    uint8_t key[16], pt[16], iv[16] = {0}, ct[64], back[64];
    from_hex(key, "000102030405060708090a0b0c0d0e0f");
    from_hex(pt, "00112233445566778899aabbccddeeff");
    size_t ct_len = sizeof(ct), back_len = sizeof(back);
    CHECK("AES-128 FIPS-197 vector", cc_aes_encrypt(CC_AES_ECB, key, 16, NULL, pt, 16, ct, &ct_len) == CC_OK &&
                                         ct_len == 32 && equals_hex(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));

    int ok = 1;
    cc_aes_mode_t modes[] = {CC_AES_ECB, CC_AES_CBC, CC_AES_CFB, CC_AES_OFB, CC_AES_CTR};
    size_t key_sizes[] = {16, 24, 32};
    uint8_t long_key[32];
    from_hex(long_key, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    for (int m = 0; m < 5; m++)
        for (int k = 0; k < 3; k++)
        {
            ct_len = sizeof(ct);
            back_len = sizeof(back);
            ok &= cc_aes_encrypt(modes[m], long_key, key_sizes[k], iv, MSG, MSG_LEN, ct, &ct_len) == CC_OK &&
                  cc_aes_decrypt(modes[m], long_key, key_sizes[k], iv, ct, ct_len, back, &back_len) == CC_OK &&
                  back_len == MSG_LEN && memcmp(back, MSG, MSG_LEN) == 0;
        }
    CHECK("AES round trip, 5 modes x 3 key sizes", ok);

    ct_len = sizeof(ct);
    ok = cc_aes_encrypt(CC_AES_CBC, key, 16, iv, MSG, MSG_LEN, ct, &ct_len) == CC_OK;
    back_len = sizeof(back);
    ok &= cc_aes_decrypt(CC_AES_CBC, long_key + 16, 16, iv, ct, ct_len, back, &back_len) == CC_ERR_DECRYPT;
    ok &= cc_aes_decrypt(CC_AES_CBC, key, 16, iv, ct, ct_len - 1, back, &back_len) == CC_ERR_INVALID_INPUT;
    ok &= cc_aes_encrypt(CC_AES_CBC, key, 20, iv, MSG, MSG_LEN, ct, &ct_len) == CC_ERR_INVALID_ARG;
    ok &= cc_aes_encrypt(CC_AES_CBC, key, 16, NULL, MSG, MSG_LEN, ct, &ct_len) == CC_ERR_INVALID_ARG;
    ct_len = 16;
    ok &= cc_aes_encrypt(CC_AES_CBC, key, 16, iv, MSG, MSG_LEN, ct, &ct_len) == CC_ERR_BUFFER_TOO_SMALL && ct_len == 32;
    CHECK("AES errors (key, length, key size, IV, buffer)", ok);

    FILE *f = fopen("api_plain.txt", "wb");
    if (f != NULL)
    {
        fwrite(MSG, 1, MSG_LEN, f);
        fclose(f);
    }
    ok = cc_aes_encrypt_file(CC_AES_CTR, key, 16, iv, "api_plain.txt", "api_aes.enc") == CC_OK &&
         cc_aes_decrypt_file(CC_AES_CTR, key, 16, iv, "api_aes.enc", "api_aes.dec") == CC_OK &&
         cc_aes_decrypt_file(CC_AES_CTR, key, 16, iv, "api_missing.enc", "api_aes.dec") == CC_ERR_IO;
    f = fopen("api_aes.dec", "rb");
    size_t read = f != NULL ? fread(back, 1, sizeof(back), f) : 0;
    if (f != NULL)
        fclose(f);
    CHECK("AES file round trip", ok && read == MSG_LEN && memcmp(back, MSG, MSG_LEN) == 0);
}

static void test_des(void)
{
    // FIPS 46-3 worked example
    uint8_t key[8], pt[8], ct[32], back[32];
    from_hex(key, "133457799bbcdff1");
    from_hex(pt, "0123456789abcdef");
    size_t ct_len = sizeof(ct), back_len = sizeof(back);
    CHECK("DES FIPS 46 vector", cc_des_encrypt(key, pt, 8, ct, &ct_len) == CC_OK && ct_len == 16 &&
                                    equals_hex(ct, 8, "85e813540f0ab405"));

    ct_len = sizeof(ct);
    int ok = cc_des_encrypt(key, MSG, MSG_LEN, ct, &ct_len) == CC_OK &&
             cc_des_decrypt(key, ct, ct_len, back, &back_len) == CC_OK &&
             back_len == MSG_LEN && memcmp(back, MSG, MSG_LEN) == 0;
    key[0] ^= 0x02;
    back_len = sizeof(back);
    ok &= cc_des_decrypt(key, ct, ct_len, back, &back_len) == CC_ERR_DECRYPT;
    CHECK("DES round trip and wrong key", ok);

    key[0] ^= 0x02;
    ok = cc_des_encrypt_file(key, "api_plain.txt", "api_des.enc") == CC_OK &&
         cc_des_decrypt_file(key, "api_des.enc", "api_des.dec") == CC_OK;
    CHECK("DES file round trip", ok);
}

static void test_mac(void)
{
    // RFC 4231 test case 2
    const uint8_t *key = (const uint8_t *)"Jefe";
    const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
    uint8_t mac[64];
    size_t mac_len = sizeof(mac);
    CHECK("HMAC-SHA256 RFC 4231 vector", cc_hmac(CC_HASH_SHA2, CC_SEC_128, key, 4, data, 28, mac, &mac_len) == CC_OK &&
                                             equals_hex(mac, mac_len, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    int ok = cc_hmac_verify(CC_HASH_SHA2, CC_SEC_128, key, 4, data, 28, mac, mac_len) == CC_OK &&
             cc_hmac_verify(CC_HASH_SHA2, CC_SEC_128, key, 4, data, 27, mac, mac_len) == CC_ERR_VERIFY &&
             cc_hmac_verify(CC_HASH_SHA2, CC_SEC_128, key, 4, data, 28, mac, mac_len - 1) == CC_ERR_VERIFY;
    mac_len = sizeof(mac);
    ok &= cc_hmac_file(CC_HASH_SHA3, CC_SEC_256, key, 4, "api_plain.txt", mac, &mac_len) == CC_OK && mac_len == 64;
    CHECK("HMAC verify and file", ok);

    mac_len = sizeof(mac);
    ok = cc_cbc_mac(CC_SEC_256, key, 4, data, 28, mac, &mac_len) == CC_OK && mac_len == 16 &&
         cc_cbc_mac_verify(CC_SEC_256, key, 4, data, 28, mac, mac_len) == CC_OK &&
         cc_cbc_mac_verify(CC_SEC_256, key, 4, data, 27, mac, mac_len) == CC_ERR_VERIFY &&
         cc_cbc_mac(CC_SEC_112, key, 4, data, 28, mac, &mac_len) == CC_ERR_INVALID_ARG;
    mac_len = sizeof(mac);
    ok &= cc_cbc_mac_file(CC_SEC_128, key, 4, "api_plain.txt", mac, &mac_len) == CC_OK;
    CHECK("CBC-MAC", ok);
}

static void test_rsa(cc_rsa_scheme_t scheme, const char *name)
{
    char label[64];
    cc_rsa_t *rsa = NULL;
    uint8_t ct[512], back[512], sig[512], msg[] = {0x00, 0x00, 'H', 'i'};
    size_t ct_len = sizeof(ct), back_len = sizeof(back), sig_len = sizeof(sig), k = 0;
    // Textbook RSA works on integers: leading zero bytes are not preserved
    const uint8_t *m = scheme == CC_RSA_TEXTBOOK ? msg + 2 : msg;
    size_t m_len = scheme == CC_RSA_TEXTBOOK ? 2 : sizeof(msg);

    int ok = cc_rsa_new(&rsa, CC_SEC_112, scheme) == CC_OK &&
             cc_rsa_encrypt(rsa, m, m_len, ct, &ct_len) == CC_ERR_NO_KEY &&
             cc_rsa_keygen(rsa) == CC_OK && cc_rsa_keygen(rsa) == CC_OK &&
             cc_rsa_size(rsa, &k) == CC_OK && k == 256;
    snprintf(label, sizeof(label), "RSA %s: setup and keygen", name);
    CHECK(label, ok);

    ok = 1;
    for (int crt = 0; crt <= 1; crt++)
    {
        ct_len = sizeof(ct), back_len = sizeof(back), sig_len = sizeof(sig);
        ok &= cc_rsa_use_crt(rsa, crt) == CC_OK &&
              cc_rsa_encrypt(rsa, m, m_len, ct, &ct_len) == CC_OK &&
              cc_rsa_decrypt(rsa, ct, ct_len, back, &back_len) == CC_OK &&
              back_len == m_len && memcmp(back, m, m_len) == 0 &&
              cc_rsa_sign(rsa, m, m_len, sig, &sig_len) == CC_OK &&
              cc_rsa_verify(rsa, m, m_len, sig, sig_len) == CC_OK &&
              cc_rsa_verify(rsa, (const uint8_t *)"Ho", 2, sig, sig_len) == CC_ERR_VERIFY;
    }
    snprintf(label, sizeof(label), "RSA %s: encrypt, decrypt, sign, verify", name);
    CHECK(label, ok);

    size_t n_len = 0, e_len = sizeof(back);
    ok = cc_rsa_get(rsa, CC_RSA_N, NULL, &n_len) == CC_ERR_BUFFER_TOO_SMALL && n_len == 256 &&
         cc_rsa_get(rsa, CC_RSA_E, back, &e_len) == CC_OK && equals_hex(back, e_len, "010001") &&
         cc_rsa_get(rsa, (cc_rsa_param_t)42, back, &e_len) == CC_ERR_INVALID_ARG;
    if (scheme != CC_RSA_TEXTBOOK)
    {
        memset(ct, 0xff, k);
        back_len = sizeof(back);
        ok &= cc_rsa_decrypt(rsa, ct, k, back, &back_len) == CC_ERR_DECRYPT &&
              cc_rsa_encrypt(rsa, ct, k, ct, &ct_len) == CC_ERR_MSG_TOO_LONG;
    }
    snprintf(label, sizeof(label), "RSA %s: key export and errors", name);
    CHECK(label, ok);
    cc_rsa_free(rsa);
}

static void test_dl(void)
{
    cc_elgamal_t *elgamal = NULL;
    uint8_t c1[512], c2[512], back[512], r[512], s[512];
    size_t c1_len = sizeof(c1), c2_len = sizeof(c2), back_len = sizeof(back), r_len = sizeof(r), s_len = sizeof(s);

    int ok = cc_elgamal_new(&elgamal, CC_SEC_112) == CC_OK && cc_elgamal_keygen(elgamal) == CC_OK &&
             cc_elgamal_encrypt(elgamal, MSG, MSG_LEN, c1, &c1_len, c2, &c2_len) == CC_OK &&
             cc_elgamal_decrypt(elgamal, c1, c1_len, c2, c2_len, back, &back_len) == CC_OK &&
             back_len == MSG_LEN && memcmp(back, MSG, MSG_LEN) == 0 &&
             cc_elgamal_sign(elgamal, MSG, MSG_LEN, r, &r_len, s, &s_len) == CC_OK &&
             cc_elgamal_verify(elgamal, MSG, MSG_LEN, r, r_len, s, s_len) == CC_OK &&
             cc_elgamal_verify(elgamal, MSG, MSG_LEN - 1, r, r_len, s, s_len) == CC_ERR_VERIFY;
    back_len = sizeof(back);
    ok &= cc_elgamal_decrypt(elgamal, (const uint8_t *)"\0", 1, c2, c2_len, back, &back_len) == CC_ERR_INVALID_INPUT;
    ok &= cc_elgamal_get(elgamal, CC_DL_Q, back, &back_len) == CC_ERR_UNSUPPORTED;
    cc_elgamal_free(elgamal);
    ok &= cc_elgamal_new(&elgamal, CC_SEC_256) == CC_ERR_INVALID_ARG && elgamal == NULL;
    CHECK("ElGamal", ok);

    cc_dsa_t *dsa = NULL;
    r_len = sizeof(r), s_len = sizeof(s);
    size_t q_len = sizeof(back);
    ok = cc_dsa_new(&dsa, CC_SEC_128, CC_HASH_SHA3) == CC_OK &&
         cc_dsa_sign(dsa, MSG, MSG_LEN, r, &r_len, s, &s_len) == CC_ERR_NO_KEY &&
         cc_dsa_keygen(dsa) == CC_OK &&
         cc_dsa_sign(dsa, MSG, MSG_LEN, r, &r_len, s, &s_len) == CC_OK &&
         cc_dsa_verify(dsa, MSG, MSG_LEN, r, r_len, s, s_len) == CC_OK &&
         cc_dsa_verify(dsa, MSG, MSG_LEN, s, s_len, r, r_len) == CC_ERR_VERIFY &&
         cc_dsa_get(dsa, CC_DL_Q, back, &q_len) == CC_OK && q_len == 32;
    cc_dsa_free(dsa);
    ok &= cc_dsa_new(&dsa, CC_SEC_128, CC_HASH_MD5) == CC_ERR_INVALID_ARG;
    CHECK("DSA", ok);

    uint8_t a[512], b[512], pa[512], pb[512], sa[512], sb[512];
    size_t a_len = sizeof(a), b_len = sizeof(b), pa_len = sizeof(pa), pb_len = sizeof(pb), sa_len = sizeof(sa), sb_len = sizeof(sb);
    ok = cc_dh_generate_secret(CC_SEC_112, a, &a_len) == CC_OK && cc_dh_generate_secret(CC_SEC_112, b, &b_len) == CC_OK &&
         cc_dh_public(CC_SEC_112, a, a_len, pa, &pa_len) == CC_OK && cc_dh_public(CC_SEC_112, b, b_len, pb, &pb_len) == CC_OK &&
         cc_dh_shared_secret(CC_SEC_112, a, a_len, pb, pb_len, sa, &sa_len) == CC_OK &&
         cc_dh_shared_secret(CC_SEC_112, b, b_len, pa, pa_len, sb, &sb_len) == CC_OK &&
         sa_len == sb_len && memcmp(sa, sb, sa_len) == 0 &&
         cc_dh_shared_secret(CC_SEC_112, a, a_len, (const uint8_t *)"\1", 1, sa, &sa_len) == CC_ERR_INVALID_INPUT;
    CHECK("Diffie-Hellman", ok);
}

static void test_ec(cc_curve_t curve, const char *name, int can_sign)
{
    char label[64];
    uint8_t c1[256], c2[64], back[64], r[128], s[128], pub[256];
    size_t c1_len = sizeof(c1), c2_len = sizeof(c2), back_len = sizeof(back), r_len = sizeof(r), s_len = sizeof(s), pub_len = sizeof(pub);
    const uint8_t msg[] = {0x00, 'E', 'C'};

    cc_ecelgamal_t *ecelgamal = NULL;
    int ok = cc_ecelgamal_new(&ecelgamal, curve, CC_HASH_SHA2) == CC_OK && cc_ecelgamal_keygen(ecelgamal) == CC_OK &&
             cc_ecelgamal_get(ecelgamal, CC_EC_PUBLIC, pub, &pub_len) == CC_OK &&
             cc_ecelgamal_encrypt(ecelgamal, msg, sizeof(msg), c1, &c1_len, c2, &c2_len) == CC_OK &&
             c1_len == pub_len && c2_len == sizeof(msg) &&
             cc_ecelgamal_decrypt(ecelgamal, c1, c1_len, c2, c2_len, back, &back_len) == CC_OK &&
             back_len == sizeof(msg) && memcmp(back, msg, sizeof(msg)) == 0;
    memset(c1, 0xff, c1_len);
    back_len = sizeof(back);
    ok &= cc_ecelgamal_decrypt(ecelgamal, c1, c1_len, c2, c2_len, back, &back_len) == CC_ERR_INVALID_INPUT;
    cc_status_t sign = cc_ecelgamal_sign(ecelgamal, MSG, MSG_LEN, r, &r_len, s, &s_len);
    ok &= can_sign ? sign == CC_OK && cc_ecelgamal_verify(ecelgamal, MSG, MSG_LEN, r, r_len, s, s_len) == CC_OK
                   : sign == CC_ERR_UNSUPPORTED;
    cc_ecelgamal_free(ecelgamal);
    snprintf(label, sizeof(label), "EC-ElGamal %s", name);
    CHECK(label, ok);

    cc_ecdsa_t *ecdsa = NULL;
    r_len = sizeof(r), s_len = sizeof(s);
    if (can_sign)
        ok = cc_ecdsa_new(&ecdsa, curve, CC_HASH_SHA3) == CC_OK && cc_ecdsa_keygen(ecdsa) == CC_OK &&
             cc_ecdsa_sign(ecdsa, MSG, MSG_LEN, r, &r_len, s, &s_len) == CC_OK &&
             cc_ecdsa_verify(ecdsa, MSG, MSG_LEN, r, r_len, s, s_len) == CC_OK &&
             cc_ecdsa_verify(ecdsa, MSG, MSG_LEN - 1, r, r_len, s, s_len) == CC_ERR_VERIFY;
    else
        ok = cc_ecdsa_new(&ecdsa, curve, CC_HASH_SHA3) == CC_ERR_UNSUPPORTED && ecdsa == NULL;
    cc_ecdsa_free(ecdsa);
    snprintf(label, sizeof(label), "ECDSA %s", name);
    CHECK(label, ok);

    uint8_t a[128], b[128], pa[256], pb[256], sa[128], sb[128];
    size_t a_len = sizeof(a), b_len = sizeof(b), pa_len = sizeof(pa), pb_len = sizeof(pb), sa_len = sizeof(sa), sb_len = sizeof(sb);
    ok = cc_ecdh_generate_secret(curve, a, &a_len) == CC_OK && cc_ecdh_generate_secret(curve, b, &b_len) == CC_OK &&
         cc_ecdh_public(curve, a, a_len, pa, &pa_len) == CC_OK && cc_ecdh_public(curve, b, b_len, pb, &pb_len) == CC_OK &&
         cc_ecdh_shared_secret(curve, a, a_len, pb, pb_len, sa, &sa_len) == CC_OK &&
         cc_ecdh_shared_secret(curve, b, b_len, pa, pa_len, sb, &sb_len) == CC_OK &&
         sa_len == sb_len && memcmp(sa, sb, sa_len) == 0 &&
         cc_ecdh_shared_secret(curve, a, a_len, pb, pb_len - 1, sa, &sa_len) == CC_ERR_INVALID_INPUT;
    snprintf(label, sizeof(label), "ECDH %s", name);
    CHECK(label, ok);
}

int main(void)
{
    printf("\n===================== PUBLIC API TEST =====================\n\n");

    test_status();
    test_hash();
    test_random_and_primes();
    test_aes();
    test_des();
    test_mac();
    test_rsa(CC_RSA_TEXTBOOK, "textbook");
    test_rsa(CC_RSA_PKCS1, "PKCS#1 v1.5");
    test_rsa(CC_RSA_OAEP_PSS, "OAEP/PSS");
    test_dl();
    test_ec(CC_CURVE_P256, "P-256", 1);
    test_ec(CC_CURVE_SECP256K1, "secp256k1", 1);
    test_ec(CC_CURVE_ED25519, "Ed25519", 1);
    test_ec(CC_CURVE_25519, "Curve25519", 0);
    test_ec(CC_CURVE_448, "Curve448", 0);

    cc_ecdsa_t *ecdsa = NULL;
    CHECK("Invalid curve", cc_ecdsa_new(&ecdsa, (cc_curve_t)99, CC_HASH_SHA2) == CC_ERR_INVALID_ARG);

    printf("\n%d failure(s)\n", failures);
    return failures != 0;
}
