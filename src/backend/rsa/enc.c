#include "conversion.h"
#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"
#include "mgf.h"
#include "sha2.h"

cc_status_t rsa_setup(public_params_t *pp, sec_level_t level)
{
    const char *e;
    switch (level)
    {
    case L0:
        pp->n_bits = L0_N_BITS;
        e = L0_E;
        break;
    case L1:
        pp->n_bits = L1_N_BITS;
        e = L1_E;
        break;
    case L2:
        pp->n_bits = L2_N_BITS;
        e = L2_E;
        break;
    case L3:
        pp->n_bits = L3_N_BITS;
        e = L3_E;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    mpz_init_set_str(pp->e, e, 10);
    return CC_OK;
}

void rsa_free_params(public_params_t *pp)
{
    mpz_clear(pp->e);
}

cc_status_t rsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    // Initialize all MPZ variables
    mpz_inits(sk->n, sk->p, sk->q, sk->d, sk->dp, sk->dq, sk->q_inv, pk->n, pk->e, NULL);

    // Set public exponent
    mpz_set(pk->e, pp->e);

    mpz_t p_1, q_1, phi_n, gcd;
    mpz_inits(p_1, q_1, phi_n, gcd, NULL);

    // Generate two distinct primes of equal size
    cc_status_t status;
    while (1)
    {
        // Generate first prime using prime_gen interface
        status = gen_prime_b(sk->p, state, pp->n_bits / 2, 100, 25, MILLER_RABIN_TEST);
        if (status != CC_OK)
            break;

        // Generate second prime
        do
        {
            status = gen_prime_b(sk->q, state, pp->n_bits / 2, 100, 25, MILLER_RABIN_TEST);
        } while (status == CC_OK && mpz_cmp(sk->p, sk->q) == 0);
        if (status != CC_OK)
            break;

        // Compute n = p * q, which must have exactly n_bits bits
        mpz_mul(sk->n, sk->p, sk->q);
        if (mpz_sizeinbase(sk->n, 2) != (size_t)pp->n_bits)
            continue;
        mpz_set(pk->n, sk->n);

        // Compute φ(n) = (p-1)(q-1)
        mpz_sub_ui(p_1, sk->p, 1);
        mpz_sub_ui(q_1, sk->q, 1);
        mpz_mul(phi_n, p_1, q_1);

        // Check if e and φ(n) are coprime
        mpz_gcd(gcd, pk->e, phi_n);
        if (mpz_cmp_ui(gcd, 1) == 0)
        {
            // Compute private exponent d = e^(-1) mod φ(n)
            mpz_invert(sk->d, pk->e, phi_n);

            // Compute CRT components
            mpz_mod(sk->dp, sk->d, p_1);         // dp = d mod (p-1)
            mpz_mod(sk->dq, sk->d, q_1);         // dq = d mod (q-1)
            mpz_invert(sk->q_inv, sk->q, sk->p); // q_inv = q^(-1) mod p
            break;
        }
    }

    // Clear temporary variables
    mpz_clears(p_1, q_1, phi_n, gcd, NULL);
    gmp_randclear(state);
    if (status != CC_OK)
        rsa_free_keys(sk, pk);
    return status;
}

void rsa_free_keys(priv_key_t *sk, pub_key_t *pk)
{
    mpz_clears(sk->n, sk->p, sk->q, sk->d, sk->dp, sk->dq, sk->q_inv, pk->n, pk->e, NULL);
}

size_t rsa_modulus_size(const mpz_t n)
{
    return count_bytes(n);
}

cc_status_t rsa_hash_length(sec_level_t sec_level, size_t *hash_len)
{
    switch (sec_level)
    {
    case L0:
        *hash_len = SHA224_DIGEST_SIZE;
        return CC_OK;
    case L1:
        *hash_len = SHA256_DIGEST_SIZE;
        return CC_OK;
    case L2:
        *hash_len = SHA384_DIGEST_SIZE;
        return CC_OK;
    case L3:
        *hash_len = SHA512_DIGEST_SIZE;
        return CC_OK;
    default:
        return CC_ERR_INVALID_ARG;
    }
}

void rsa_public_op(mpz_t r, const mpz_t x, const pub_key_t *pk)
{
    // r = x^e mod n
    mpz_powm(r, x, pk->e, pk->n);
}

cc_status_t rsa_private_op(mpz_t r, const mpz_t x, const priv_key_t *sk, rsa_algo_t algorithm)
{
    if (algorithm == RSA_STANDARD)
    {
        // r = x^d mod n
        mpz_powm(r, x, sk->d, sk->n);
    }
    else if (algorithm == RSA_CRT)
    {
        // Chinese Remainder Theorem (CRT) optimization
        mpz_t m1, m2, h;
        mpz_inits(m1, m2, h, NULL);

        // m1 = x^dp mod p
        mpz_powm(m1, x, sk->dp, sk->p);

        // m2 = x^dq mod q
        mpz_powm(m2, x, sk->dq, sk->q);

        // h = q_inv * (m1 - m2) mod p
        mpz_sub(h, m1, m2);
        if (mpz_sgn(h) < 0)
        {
            mpz_add(h, h, sk->p);
        }
        mpz_mul(h, sk->q_inv, h);
        mpz_mod(h, h, sk->p);

        // r = m2 + h * q
        mpz_mul(h, h, sk->q);
        mpz_add(r, m2, h);

        mpz_clears(m1, m2, h, NULL);
    }
    else
    {
        return CC_ERR_INVALID_ARG;
    }
    return CC_OK;
}

cc_status_t rsa_encrypt(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    if (mpz_sgn(m) < 0 || mpz_cmp(m, pk->n) >= 0)
        return CC_ERR_MSG_TOO_LONG;
    rsa_public_op(c, m, pk);
    return CC_OK;
}

cc_status_t rsa_decrypt(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm)
{
    if (mpz_sgn(c) < 0 || mpz_cmp(c, sk->n) >= 0)
        return CC_ERR_INVALID_INPUT;
    return rsa_private_op(m, c, sk, algorithm);
}

// Applies the private key to a k-byte block: out = (in^d mod n) as k bytes
static cc_status_t private_op_bytes(unsigned char *out, const unsigned char *in, size_t k, const priv_key_t *sk, rsa_algo_t algorithm, cc_status_t invalid)
{
    mpz_t x;
    mpz_init(x);
    bytes_to_bigint(x, in, k, BIG);

    cc_status_t status = invalid;
    if (mpz_cmp(x, sk->n) < 0)
        status = rsa_private_op(x, x, sk, algorithm);
    if (status == CC_OK)
        status = bigint_to_bytes_fixed(out, k, x);

    mpz_clear(x);
    return status;
}

// Applies the public key to a k-byte block: out = (in^e mod n) as k bytes
static cc_status_t public_op_bytes(unsigned char *out, const unsigned char *in, size_t k, const pub_key_t *pk, cc_status_t invalid)
{
    mpz_t x;
    mpz_init(x);
    bytes_to_bigint(x, in, k, BIG);

    cc_status_t status = invalid;
    if (mpz_cmp(x, pk->n) < 0)
    {
        rsa_public_op(x, x, pk);
        status = bigint_to_bytes_fixed(out, k, x);
    }

    mpz_clear(x);
    return status;
}

static cc_status_t eme_pkcs1_encode(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len)
{
    // Generate padding
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    em[0] = 0x00;
    em[1] = 0x02;
    for (size_t i = 2; i < em_len - m_len - 1; i++)
    {
        em[i] = 0x00;
        while (em[i] == 0x00)
        {
            rand_bytes((char *)(em + i), state, 1);
        }
    }
    em[em_len - m_len - 1] = 0x00;

    // Copy message
    memcpy(em + em_len - m_len, m, m_len);

    gmp_randclear(state);
    return CC_OK;
}

cc_status_t rsa_encrypt_pkcs1(unsigned char *c, const unsigned char *m, size_t m_len, const pub_key_t *pk)
{
    size_t k = rsa_modulus_size(pk->n);
    if (k < 11 || m_len > k - 11)
        return CC_ERR_MSG_TOO_LONG;

    unsigned char *em = malloc(k);
    if (em == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = eme_pkcs1_encode(em, k, m, m_len);
    if (status == CC_OK)
        status = public_op_bytes(c, em, k, pk, CC_ERR_INVALID_INPUT);

    free(em);
    return status;
}

cc_status_t rsa_decrypt_pkcs1(unsigned char *m, size_t *m_len, const unsigned char *c, size_t c_len, const priv_key_t *sk, rsa_algo_t algorithm)
{
    size_t k = rsa_modulus_size(sk->n);
    if (c_len != k || k < 11)
        return CC_ERR_DECRYPT;

    unsigned char *em = malloc(k);
    if (em == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = private_op_bytes(em, c, k, sk, algorithm, CC_ERR_DECRYPT);

    // EM = 0x00 || 0x02 || PS (at least 8 non-zero bytes) || 0x00 || M
    size_t i = 2;
    if (status == CC_OK)
    {
        while (i < k && em[i] != 0x00)
            i++;
        if (em[0] != 0x00 || em[1] != 0x02 || i == k || i < 10)
            status = CC_ERR_DECRYPT;
    }
    if (status == CC_OK)
    {
        *m_len = k - i - 1;
        memcpy(m, em + i + 1, *m_len);
    }

    free(em);
    return status;
}

static cc_status_t eme_oaep_encode(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    size_t hash_len;
    CC_TRY(rsa_hash_length(sec_level, &hash_len));

    if (em_len < 2 * hash_len + 2 || m_len > em_len - 2 * hash_len - 2)
        return CC_ERR_MSG_TOO_LONG;

    // DB = lHash || PS || 0x01 || M, with an empty label
    size_t db_len = em_len - hash_len - 1;
    unsigned char *db = malloc(db_len);
    unsigned char *seed = malloc(hash_len);
    unsigned char *db_mask = malloc(db_len);
    unsigned char *seed_mask = malloc(hash_len);
    gmp_randstate_t state;
    cc_status_t status = CC_OK;

    if (db == NULL || seed == NULL || db_mask == NULL || seed_mask == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
        status = rng_init(state);
    if (status == CC_OK)
    {
        sha2("", 0, db, hash_len);
        memset(db + hash_len, 0x00, db_len - m_len - hash_len - 1);
        db[db_len - m_len - 1] = 0x01;
        memcpy(db + db_len - m_len, m, m_len);

        // Generate seed
        rand_bytes((char *)seed, state, hash_len);
        gmp_randclear(state);

        // maskedDB = DB ^ MGF(seed), maskedSeed = seed ^ MGF(maskedDB)
        status = mgf1(db_mask, db_len, seed, hash_len, SHA2, sec_level);
    }
    if (status == CC_OK)
    {
        for (size_t i = 0; i < db_len; i++)
            db[i] ^= db_mask[i];
        status = mgf1(seed_mask, hash_len, db, db_len, SHA2, sec_level);
    }
    if (status == CC_OK)
    {
        for (size_t i = 0; i < hash_len; i++)
            seed[i] ^= seed_mask[i];

        // EM = 0x00 || maskedSeed || maskedDB
        em[0] = 0x00;
        memcpy(em + 1, seed, hash_len);
        memcpy(em + 1 + hash_len, db, db_len);
    }

    free(db);
    free(seed);
    free(db_mask);
    free(seed_mask);
    return status;
}

cc_status_t rsa_encrypt_oaep(unsigned char *c, const unsigned char *m, size_t m_len, const pub_key_t *pk, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(pk->n);
    unsigned char *em = malloc(k);
    if (em == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = eme_oaep_encode(em, k, m, m_len, sec_level);
    if (status == CC_OK)
        status = public_op_bytes(c, em, k, pk, CC_ERR_INVALID_INPUT);

    free(em);
    return status;
}

cc_status_t rsa_decrypt_oaep(unsigned char *m, size_t *m_len, const unsigned char *c, size_t c_len, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    size_t k = rsa_modulus_size(sk->n);
    size_t hash_len;
    CC_TRY(rsa_hash_length(sec_level, &hash_len));

    if (c_len != k || k < 2 * hash_len + 2)
        return CC_ERR_DECRYPT;

    size_t db_len = k - hash_len - 1;
    unsigned char *em = malloc(k);
    unsigned char *seed = malloc(hash_len);
    unsigned char *db = malloc(db_len);
    unsigned char *l_hash = malloc(hash_len);
    cc_status_t status = CC_OK;

    if (em == NULL || seed == NULL || db == NULL || l_hash == NULL)
        status = CC_ERR_NOMEM;
    if (status == CC_OK)
        status = private_op_bytes(em, c, k, sk, algorithm, CC_ERR_DECRYPT);

    // EM = Y || maskedSeed || maskedDB: seed = maskedSeed ^ MGF(maskedDB), DB = maskedDB ^ MGF(seed)
    if (status == CC_OK)
        status = mgf1(seed, hash_len, em + 1 + hash_len, db_len, SHA2, sec_level);
    if (status == CC_OK)
    {
        for (size_t i = 0; i < hash_len; i++)
            seed[i] ^= em[1 + i];
        status = mgf1(db, db_len, seed, hash_len, SHA2, sec_level);
    }

    // DB = lHash || PS (zeros) || 0x01 || M
    size_t i = hash_len;
    if (status == CC_OK)
    {
        for (size_t j = 0; j < db_len; j++)
            db[j] ^= em[1 + hash_len + j];
        sha2("", 0, l_hash, hash_len);

        while (i < db_len && db[i] == 0x00)
            i++;
        if (em[0] != 0x00 || memcmp(db, l_hash, hash_len) != 0 || i == db_len || db[i] != 0x01)
            status = CC_ERR_DECRYPT;
    }
    if (status == CC_OK)
    {
        *m_len = db_len - i - 1;
        memcpy(m, db + i + 1, *m_len);
    }

    free(em);
    free(seed);
    free(db);
    free(l_hash);
    return status;
}
