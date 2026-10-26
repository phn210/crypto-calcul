#include "rsa.h"
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

cc_status_t rsa_sign(mpz_t s, const mpz_t m, const priv_key_t *sk, rsa_algo_t algorithm)
{
    if (mpz_sgn(m) < 0 || mpz_cmp(m, sk->n) >= 0)
        return CC_ERR_MSG_TOO_LONG;
    return rsa_private_op(s, m, sk, algorithm);
}

cc_status_t rsa_verify(const mpz_t m, const mpz_t s, const pub_key_t *pk)
{
    if (mpz_sgn(s) < 0 || mpz_cmp(s, pk->n) >= 0)
        return CC_ERR_VERIFY;

    mpz_t m_check;
    mpz_init(m_check);

    // Verify: m ?= s^e mod n
    rsa_public_op(m_check, s, pk);

    int valid = mpz_cmp(m, m_check) == 0;
    mpz_clear(m_check);
    return valid ? CC_OK : CC_ERR_VERIFY;
}

// EM = 0x00 || 0x01 || PS (0xff) || 0x00 || DigestInfo || H(m)
static cc_status_t emsa_pkcs1_encode(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    const unsigned char *hash_id;
    switch (sec_level)
    {
    case L0:
        hash_id = pkcs1_sha224;
        break;
    case L1:
        hash_id = pkcs1_sha256;
        break;
    case L2:
        hash_id = pkcs1_sha384;
        break;
    case L3:
        hash_id = pkcs1_sha512;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    size_t md_len;
    CC_TRY(rsa_hash_length(sec_level, &md_len));

    // Intended encoded message length too short for this hash
    size_t t_len = HASH_ID_SIZE + md_len;
    if (em_len < t_len + 11)
        return CC_ERR_INVALID_ARG;

    em[0] = 0x00;
    em[1] = 0x01;
    memset(em + 2, 0xff, em_len - t_len - 3);
    em[em_len - t_len - 1] = 0x00;
    memcpy(em + em_len - t_len, hash_id, HASH_ID_SIZE);
    sha2(m, m_len, em + em_len - md_len, md_len);
    return CC_OK;
}

cc_status_t rsa_sign_pkcs1(unsigned char *s, const unsigned char *m, size_t m_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(sk->n);
    unsigned char *em = malloc(k);
    if (em == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = emsa_pkcs1_encode(em, k, m, m_len, sec_level);

    mpz_t x;
    mpz_init(x);
    if (status == CC_OK)
    {
        bytes_to_bigint(x, em, k, BIG);
        status = rsa_private_op(x, x, sk, algorithm);
    }
    if (status == CC_OK)
        status = bigint_to_bytes_fixed(s, k, x);

    mpz_clear(x);
    free(em);
    return status;
}

cc_status_t rsa_verify_pkcs1(const unsigned char *m, size_t m_len, const unsigned char *s, size_t s_len, const pub_key_t *pk, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(pk->n);
    if (s_len != k)
        return CC_ERR_VERIFY;

    unsigned char *em = malloc(k);
    unsigned char *em_check = malloc(k);
    mpz_t x;
    mpz_init(x);
    bytes_to_bigint(x, s, s_len, BIG);

    cc_status_t status = CC_OK;
    if (em == NULL || em_check == NULL)
        status = CC_ERR_NOMEM;
    else if (mpz_cmp(x, pk->n) >= 0)
        status = CC_ERR_VERIFY;
    if (status == CC_OK)
        status = emsa_pkcs1_encode(em, k, m, m_len, sec_level);
    if (status == CC_OK)
    {
        rsa_public_op(x, x, pk);
        if (bigint_to_bytes_fixed(em_check, k, x) != CC_OK || memcmp(em, em_check, k) != 0)
            status = CC_ERR_VERIFY;
    }

    mpz_clear(x);
    free(em);
    free(em_check);
    return status;
}

// M' = 0x00 * 8 || H(m) || salt, then H(M')
static void pss_hash(unsigned char *h, const unsigned char *m_hash, const unsigned char *salt, size_t hash_len, unsigned char *m_prime)
{
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, m_hash, hash_len);
    memcpy(m_prime + 8 + hash_len, salt, hash_len);
    sha2(m_prime, 8 + 2 * hash_len, h, hash_len);
}

// EM = maskedDB || H || 0xbc over em_bits bits, with a salt as long as the hash
static cc_status_t emsa_pss_encode(unsigned char *em, size_t em_bits, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    size_t em_len = (em_bits + 7) / 8;
    size_t hash_len;
    CC_TRY(rsa_hash_length(sec_level, &hash_len));
    if (em_len < 2 * hash_len + 2)
        return CC_ERR_INVALID_ARG;

    size_t db_len = em_len - hash_len - 1;
    unsigned char *m_hash = malloc(hash_len);
    unsigned char *salt = malloc(hash_len);
    unsigned char *m_prime = malloc(8 + 2 * hash_len);
    unsigned char *db_mask = malloc(db_len);
    gmp_randstate_t state;
    cc_status_t status = CC_OK;

    if (m_hash == NULL || salt == NULL || m_prime == NULL || db_mask == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
        status = rng_init(state);
    if (status == CC_OK)
    {
        rand_bytes((char *)salt, state, hash_len);
        gmp_randclear(state);

        sha2(m, m_len, m_hash, hash_len);
        unsigned char *h = em + db_len;
        pss_hash(h, m_hash, salt, hash_len, m_prime);

        // DB = PS (zeros) || 0x01 || salt
        memset(em, 0, db_len - hash_len - 1);
        em[db_len - hash_len - 1] = 0x01;
        memcpy(em + db_len - hash_len, salt, hash_len);

        status = mgf1(db_mask, db_len, h, hash_len, SHA2, sec_level);
    }
    if (status == CC_OK)
    {
        for (size_t i = 0; i < db_len; i++)
            em[i] ^= db_mask[i];
        em[0] &= 0xFF >> (8 * em_len - em_bits);
        em[em_len - 1] = 0xBC;
    }

    free(m_hash);
    free(salt);
    free(m_prime);
    free(db_mask);
    return status;
}

static cc_status_t emsa_pss_verify(const unsigned char *em, size_t em_bits, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    size_t em_len = (em_bits + 7) / 8;
    size_t hash_len;
    CC_TRY(rsa_hash_length(sec_level, &hash_len));

    size_t mask_bits = 8 * em_len - em_bits;
    if (em_len < 2 * hash_len + 2 || em[em_len - 1] != 0xBC || (em[0] & ~(0xFF >> mask_bits)) != 0)
        return CC_ERR_VERIFY;

    size_t db_len = em_len - hash_len - 1;
    const unsigned char *h = em + db_len;
    unsigned char *db = malloc(db_len);
    unsigned char *m_hash = malloc(hash_len);
    unsigned char *m_prime = malloc(8 + 2 * hash_len);
    unsigned char *h_check = malloc(hash_len);
    cc_status_t status = CC_OK;

    if (db == NULL || m_hash == NULL || m_prime == NULL || h_check == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
        status = mgf1(db, db_len, h, hash_len, SHA2, sec_level);
    if (status == CC_OK)
    {
        for (size_t i = 0; i < db_len; i++)
            db[i] ^= em[i];
        db[0] &= 0xFF >> mask_bits;

        // DB = PS (zeros) || 0x01 || salt
        size_t ps_len = db_len - hash_len - 1;
        for (size_t i = 0; i < ps_len; i++)
        {
            if (db[i] != 0x00)
                status = CC_ERR_VERIFY;
        }
        if (db[ps_len] != 0x01)
            status = CC_ERR_VERIFY;
    }
    if (status == CC_OK)
    {
        sha2(m, m_len, m_hash, hash_len);
        pss_hash(h_check, m_hash, db + db_len - hash_len, hash_len, m_prime);
        if (memcmp(h, h_check, hash_len) != 0)
            status = CC_ERR_VERIFY;
    }

    free(db);
    free(m_hash);
    free(m_prime);
    free(h_check);
    return status;
}

cc_status_t rsa_sign_pss(unsigned char *s, const unsigned char *m, size_t m_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(sk->n);
    size_t em_bits = mpz_sizeinbase(sk->n, 2) - 1;
    size_t em_len = (em_bits + 7) / 8;
    unsigned char *em = malloc(em_len);
    if (em == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = emsa_pss_encode(em, em_bits, m, m_len, sec_level);

    mpz_t x;
    mpz_init(x);
    if (status == CC_OK)
    {
        bytes_to_bigint(x, em, em_len, BIG);
        status = rsa_private_op(x, x, sk, algorithm);
    }
    if (status == CC_OK)
        status = bigint_to_bytes_fixed(s, k, x);

    mpz_clear(x);
    free(em);
    return status;
}

cc_status_t rsa_verify_pss(const unsigned char *m, size_t m_len, const unsigned char *s, size_t s_len, const pub_key_t *pk, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(pk->n);
    size_t em_bits = mpz_sizeinbase(pk->n, 2) - 1;
    size_t em_len = (em_bits + 7) / 8;
    if (s_len != k)
        return CC_ERR_VERIFY;

    unsigned char *em = malloc(em_len);
    mpz_t x;
    mpz_init(x);
    bytes_to_bigint(x, s, s_len, BIG);

    cc_status_t status = CC_OK;
    if (em == NULL)
        status = CC_ERR_NOMEM;
    else if (mpz_cmp(x, pk->n) >= 0)
        status = CC_ERR_VERIFY;
    if (status == CC_OK)
    {
        // EM is em_len bytes; a valid signature never needs more
        rsa_public_op(x, x, pk);
        if (bigint_to_bytes_fixed(em, em_len, x) != CC_OK)
            status = CC_ERR_VERIFY;
    }
    if (status == CC_OK)
        status = emsa_pss_verify(em, em_bits, m, m_len, sec_level);

    mpz_clear(x);
    free(em);
    return status;
}
