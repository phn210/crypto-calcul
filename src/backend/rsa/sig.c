#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"
#include "conversion.h"
#include "sha2.h"
#include "mgf.h"

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

void rsasp1(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm)
{
    if (algorithm == RSA_STANDARD)
    {
        // s = m^d mod n
        mpz_powm(s, m, sk->d, sk->n);
    }
    else if (algorithm == RSA_CRT)
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

void crypto_sign(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm)
{
    rsasp1(s, m, sk, algorithm);
}

int crypto_verify(const mpz_t m, const mpz_t s, const pub_key_t *pk)
{
    mpz_t m_check;
    mpz_init(m_check);

    // Verify: m ?= s^e mod n
    rsavp1(m_check, s, pk);

    int result = mpz_cmp(m, m_check) == 0;
    mpz_clear(m_check);
    return result;
}

void emsa_pkcs1_encode(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len, sec_level_t sec_level)
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
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
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

void crypto_sign_pkcs1(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);

    size_t k = count_bytes(sk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    if (em == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    emsa_pkcs1_encode(em, k, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG);

    // Sign
    rsasp1(s, padded_m, sk, algorithm);

    mpz_clear(padded_m);
    free(em);
    free(buf);
}

int crypto_verify_pkcs1(const mpz_t m, const mpz_t s, const pub_key_t *pk, sec_level_t sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);

    size_t k = count_bytes(pk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    if (em == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    emsa_pkcs1_encode(em, k, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m, signed_em;
    mpz_inits(padded_m, signed_em, NULL);
    bytes_to_bigint(padded_m, em, k, BIG);
    rsavp1(signed_em, s, pk);

    // Verify
    int result = mpz_cmp(padded_m, signed_em) == 0;

    mpz_clears(padded_m, signed_em, NULL);
    free(em);
    free(buf);

    return result;
}

void emsa_pss_encode(unsigned char *em, size_t em_bits, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    size_t em_len = (em_bits / 8) * 8 < em_bits ? (em_bits / 8) + 1 : em_bits / 8;
    size_t hash_len;

    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        break;
    case L2:
        hash_len = SHA384_DIGEST_SIZE;
        break;
    case L3:
        hash_len = SHA512_DIGEST_SIZE;
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    // Hash message
    unsigned char *m_prime = (unsigned char *)malloc(hash_len * 2 + 8);
    if (m_prime == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memset(m_prime, 0, 8);
    sha2(m, m_len, m_prime + 8, hash_len);

    // Generate salt
    unsigned char *salt = (unsigned char *)malloc(hash_len);
    if (salt == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    gmp_randstate_t state;
    rng_init(state);
    rand_bytes((char *)salt, state, hash_len);
    memcpy(m_prime + hash_len + 8, salt, hash_len);

    // Compute DB
    unsigned char *db = (unsigned char *)malloc(em_len - hash_len - 1);
    if (db == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memset(db, 0, em_len - 2 * hash_len - 2);
    db[em_len - 2 * hash_len - 2] = 0x01;
    memcpy(db + em_len - 2 * hash_len - 1, salt, hash_len);

    // Generate H
    unsigned char *h = (unsigned char *)malloc(hash_len);
    if (h == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    sha2(m_prime, hash_len * 2 + 8, h, hash_len);

    // Generate dbMask
    unsigned char *dbMask = (unsigned char *)malloc(em_len - hash_len - 1);
    if (dbMask == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    mgf1(dbMask, em_len - hash_len - 1, h, hash_len, SHA2, sec_level);
    for (unsigned int i = 0; i < em_len - hash_len - 1; i++)
    {
        db[i] ^= dbMask[i];
    }

    size_t mask_bits = em_len * 8 - em_bits;
    db[0] &= 0xFF >> mask_bits;

    memcpy(em, db, em_len - hash_len - 1);
    memcpy(em + em_len - hash_len - 1, h, hash_len);
    em[em_len - 1] = 0xBC;

    gmp_randclear(state);
    free(m_prime);
    free(salt);
    free(db);
    free(h);
    free(dbMask);
}

int emsa_pss_verify(const unsigned char *em, size_t em_bits, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    size_t em_len = (em_bits / 8) * 8 < em_bits ? (em_bits / 8) + 1 : em_bits / 8;
    size_t hash_len;

    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        break;
    case L2:
        hash_len = SHA384_DIGEST_SIZE;
        break;
    case L3:
        hash_len = SHA512_DIGEST_SIZE;
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    // Generate H
    unsigned char *h = (unsigned char *)malloc(hash_len);
    if (h == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(h, em + em_len - hash_len - 1, hash_len);

    // Verify
    size_t mask_bits = em_len * 8 - em_bits;
    if (em_len < 2 * hash_len + 2 || em[em_len - 1] != 0xBC || em[0] >> (8 - mask_bits) != 0x00)
    {
        return 0;
    }

    unsigned char *dbMask = (unsigned char *)malloc(em_len - hash_len - 1);
    if (dbMask == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    mgf1(dbMask, em_len - hash_len - 1, h, hash_len, SHA2, sec_level);

    unsigned char *db = (unsigned char *)malloc(em_len - hash_len - 1);
    if (db == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    for (unsigned int i = 0; i < em_len - hash_len - 1; i++)
    {
        db[i] = em[i] ^ dbMask[i];
    }
    db[0] &= 0xFF >> mask_bits;

    for (unsigned int i = 0; i < em_len - 2 * hash_len - 2; i++)
    {
        if (db[i] != 0x00)
        {
            return 0;
        }
    }
    if (db[em_len - 2 * hash_len - 2] != 0x01)
    {
        return 0;
    }

    unsigned char *m_check = (unsigned char *)malloc(hash_len * 2 + 8);
    if (m_check == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memset(m_check, 0, 8);
    sha2(m, m_len, m_check + 8, hash_len);
    memcpy(m_check + hash_len + 8, db + em_len - 2 * hash_len - 1, hash_len);
    sha2(m_check, hash_len * 2 + 8, m_check, hash_len);

    int result = memcmp(h, m_check, hash_len) == 0;

    free(h);
    free(dbMask);
    free(db);
    free(m_check);

    return result;
}

void crypto_sign_pss(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);

    size_t k = count_bytes(sk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    if (em == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    emsa_pss_encode(em, mpz_sizeinbase(sk->n, 2) - 1, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG);

    // Sign
    rsasp1(s, padded_m, sk, algorithm);

    mpz_clear(padded_m);
    free(em);
    free(buf);
}

int crypto_verify_pss(const mpz_t m, const mpz_t s, const pub_key_t *pk, sec_level_t sec_level)
{
    unsigned char *buf = (unsigned char *)malloc(count_bytes(m));
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);

    size_t k = count_bytes(pk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    if (em == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Convert to MPZ
    size_t em_len;
    mpz_t signed_em;
    mpz_init(signed_em);
    rsavp1(signed_em, s, pk);
    bigint_to_bytes(em, &em_len, signed_em, BIG);

    if (em_len != k)
    {
        fprintf(stderr, "Invalid signature length\n");
        exit(EXIT_FAILURE);
    }

    // Verify
    int result = emsa_pss_verify(em, mpz_sizeinbase(pk->n, 2) - 1, buf, buf_len, sec_level);

    mpz_clear(signed_em);
    free(em);
    free(buf);

    return result;
}