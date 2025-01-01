#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"
#include "conversion.h"
#include "sha2.h"

#define HASH_ID_SIZE 19

static const unsigned char pkcs1_sha224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c};

static const unsigned char pkcs1_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20};

static const unsigned char pkcs1_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30};

static const unsigned char pkcs1_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40};

void rsasp1(mpz_t s, const mpz_t m, const priv_key_t *sk, RSA_ALGORITHM algorithm)
{
    if (algorithm == STANDARD)
    {
        // s = m^d mod n
        mpz_powm(s, m, sk->d, sk->n);
    }
    else if (algorithm == CRT)
    {
        // Chinese Remainder Theorem (CRT) optimization for signing
        mpz_t s1, s2, h;
        mpz_inits(s1, s2, h, NULL);

        // s1 = m^dp mod p
        mpz_powm(s1, m, sk->dp, sk->p);

        // s2 = m^dq mod q
        mpz_powm(s2, m, sk->dq, sk->q);

        // h = q_inv * (s1 - s2) mod p
        mpz_sub(h, s1, s2);
        if (mpz_sgn(h) < 0)
        {
            mpz_add(h, h, sk->p);
        }
        mpz_mul(h, sk->q_inv, h);
        mpz_mod(h, h, sk->p);

        // s = s2 + h * q
        mpz_mul(h, h, sk->q);
        mpz_add(s, s2, h);

        mpz_clears(s1, s2, h, NULL);
    }
    else
    {
        fprintf(stderr, "Invalid RSA algorithm\n");
        exit(EXIT_FAILURE);
    }
}

void rsavp1(mpz_t m, const mpz_t s, const pub_key_t *pk)
{
    // m = s^e mod n
    mpz_powm(m, s, pk->e, pk->n);
}

void emsa_pkcs1(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len, SECURITY_LEVEL sec_level)
{
    unsigned char *md;
    size_t md_len;

    switch (sec_level)
    {
    case L0:
        md_len = SHA224_DIGEST_SIZE;
        md = (unsigned char *)malloc(HASH_ID_SIZE + md_len);
        memcpy(md, pkcs1_sha224, HASH_ID_SIZE);
        break;
    case L1:
        md_len = SHA256_DIGEST_SIZE;
        md = (unsigned char *)malloc(HASH_ID_SIZE + md_len);
        memcpy(md, pkcs1_sha256, HASH_ID_SIZE);
        break;
    case L2:
        md_len = SHA384_DIGEST_SIZE;
        md = (unsigned char *)malloc(HASH_ID_SIZE + md_len);
        memcpy(md, pkcs1_sha384, HASH_ID_SIZE);
        break;
    case L3:
        md_len = SHA512_DIGEST_SIZE;
        md = (unsigned char *)malloc(HASH_ID_SIZE + md_len);
        memcpy(md, pkcs1_sha512, HASH_ID_SIZE);
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    sha2(m, m_len, md + HASH_ID_SIZE, md_len);

    if (em_len < md_len + HASH_ID_SIZE + 11)
    {
        fprintf(stderr, "Intended encoded message length too short\n");
        exit(EXIT_FAILURE);
    }

    em[0] = 0x00;
    em[1] = 0x01;
    memset(em + 2, 0xff, em_len - md_len - HASH_ID_SIZE - 3);
    em[em_len - md_len - HASH_ID_SIZE - 1] = 0x00;
    memcpy(em + em_len - md_len - HASH_ID_SIZE, md, md_len + HASH_ID_SIZE);

    free(md);
}

void sign(mpz_t s, const mpz_t m, const priv_key_t *sk, RSA_ALGORITHM algorithm)
{
    rsasp1(s, m, sk, algorithm);
}

int verify(const mpz_t m, const mpz_t s, const pub_key_t *pk)
{
    mpz_t m_check;
    mpz_init(m_check);

    // Verify: m ?= s^e mod n
    rsavp1(m_check, s, pk);

    int result = mpz_cmp(m, m_check) == 0;
    return result;
}

void sign_pkcs1(mpz_t s, const mpz_t m, const priv_key_t *sk, RSA_ALGORITHM algorithm, SECURITY_LEVEL sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG_ENDIAN);

    size_t k = count_bytes(sk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    emsa_pkcs1(em, k, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG_ENDIAN);

    // Sign
    rsasp1(s, padded_m, sk, algorithm);

    mpz_clear(padded_m);
    free(em);
    free(buf);
}

int verify_pkcs1(const mpz_t m, const mpz_t s, const pub_key_t *pk, SECURITY_LEVEL sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG_ENDIAN);

    size_t k = count_bytes(pk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    emsa_pkcs1(em, k, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m, signed_em;
    mpz_inits(padded_m, signed_em, NULL);
    bytes_to_bigint(padded_m, em, k, BIG_ENDIAN);
    rsavp1(signed_em, s, pk);

    // Verify
    int result = mpz_cmp(padded_m, signed_em) == 0;

    mpz_clears(padded_m, signed_em, NULL);
    free(em);
    free(buf);

    return result;
}