#include "conversion.h"
#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"
#include "mgf.h"
#include "sha2.h"

static const unsigned char empty_hash_sha224[] = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
    0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
    0xc5, 0xb3, 0xe4, 0x2f};

static const unsigned char empty_hash_sha256[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static const unsigned char empty_hash_sha384[] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};

static const unsigned char empty_hash_sha512[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};

void setup(public_params_t *pp, sec_level_t level)
{
    mpz_init(pp->e);

    switch (level)
    {
    case L0:
        pp->n_bits = L0_N_BITS;
        mpz_set_str(pp->e, L0_E, 10);
        break;
    case L1:
        pp->n_bits = L1_N_BITS;
        mpz_set_str(pp->e, L1_E, 10);
        break;
    case L2:
        pp->n_bits = L2_N_BITS;
        mpz_set_str(pp->e, L2_E, 10);
        break;
    case L3:
        pp->n_bits = L3_N_BITS;
        mpz_set_str(pp->e, L3_E, 10);
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }
}

void keygen(priv_key_t *sk, pub_key_t *pk, public_params_t pp)
{
    gmp_randstate_t state;
    rng_init(state);

    // Initialize all MPZ variables
    mpz_inits(sk->n, sk->p, sk->q, sk->d, sk->dp, sk->dq, sk->q_inv, pk->n, pk->e, NULL);

    // Set public exponent
    mpz_set(pk->e, pp.e);

    mpz_t p_1, q_1, phi_n, gcd;
    mpz_inits(p_1, q_1, phi_n, gcd, NULL);

    // Generate two distinct primes of equal size
    while (1)
    {
        // Generate first prime using prime_gen interface
        gen_prime_b(sk->p, state, pp.n_bits / 2, 100, 25, MILLER_RABIN_TEST);

        // Generate second prime
        do
        {
            gen_prime_b(sk->q, state, pp.n_bits / 2, 100, 25, MILLER_RABIN_TEST);
        } while (mpz_cmp(sk->p, sk->q) == 0);

        // Compute n = p * q
        mpz_mul(sk->n, sk->p, sk->q);
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
}

void rsaep(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    // c = m^e mod n
    mpz_powm(c, m, pk->e, pk->n);
}

void rsadp(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algo)
{
    if (algo == RSA_STANDARD)
    {
        // m = c^d mod n
        mpz_powm(m, c, sk->d, sk->n);
    }
    else if (algo == RSA_CRT)
    {
        // Chinese Remainder Theorem (CRT) optimization for decryption
        mpz_t m1, m2, h;
        mpz_inits(m1, m2, h, NULL);

        // m1 = c^dp mod p
        mpz_powm(m1, c, sk->dp, sk->p);

        // m2 = c^dq mod q
        mpz_powm(m2, c, sk->dq, sk->q);

        // h = q_inv * (m1 - m2) mod p
        mpz_sub(h, m1, m2);
        if (mpz_sgn(h) < 0)
        {
            mpz_add(h, h, sk->p);
        }
        mpz_mul(h, sk->q_inv, h);
        mpz_mod(h, h, sk->p);

        // m = m2 + h * q
        mpz_mul(h, h, sk->q);
        mpz_add(m, m2, h);

        mpz_clears(m1, m2, h, NULL);
    }
    else
    {
        fprintf(stderr, "Invalid RSA algorithm\n");
        exit(EXIT_FAILURE);
    }
}

void crypto_encrypt(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    rsaep(c, m, pk);
}

void crypto_decrypt(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm)
{
    rsadp(m, c, sk, algorithm);
}

void eme_pkcs1_encode(unsigned char *em, size_t em_len, const unsigned char *m, size_t m_len)
{
    // Generate padding
    gmp_randstate_t state;
    rng_init(state);

    em[0] = 0x00;
    em[1] = 0x02;
    for (unsigned int i = 2; i < em_len - m_len - 1; i++)
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
}

void crypto_encrypt_pkcs1(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    size_t m_len = count_bytes(m);
    size_t k = count_bytes(pk->n);
    unsigned char *em = (unsigned char *)malloc(k);
    if (em == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    if (m_len > k - 11)
    {
        fprintf(stderr, "Message is too long\n");
        exit(EXIT_FAILURE);
    }

    // Convert to bytes
    unsigned char *buf = (unsigned char *)malloc(m_len);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);
    eme_pkcs1_encode(em, k, buf, buf_len);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG);

    // Encrypt
    rsaep(c, padded_m, pk);

    mpz_clear(padded_m);
    free(em);
    free(buf);
}

void crypto_decrypt_pkcs1(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm)
{
    size_t k = count_bytes(sk->n);
    size_t c_len = count_bytes(c);

    if (c_len != k || k < 11)
    {
        fprintf(stderr, "Invalid ciphertext\n");
        exit(EXIT_FAILURE);
    }

    // Decrypt
    rsadp(m, c, sk, algorithm);

    // Convert to bytes
    unsigned char *buf = (unsigned char *)malloc(k);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    buf[0] = 0x00;
    bigint_to_bytes(buf + 1, &buf_len, m, BIG);

    // Check padding
    if (buf[0] != 0x00 || buf[1] != 0x02)
    {
        fprintf(stderr, "Invalid padding\n");
        exit(EXIT_FAILURE);
    }

    // Find zero byte
    int i = 2;
    while (buf[i] != 0x00)
    {
        i++;
    }
    // Copy message
    bytes_to_bigint(m, buf + i + 1, k - i - 1, BIG);
    free(buf);
}

void eme_oaep_encode(unsigned char *em, size_t em_len, unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    // Generate padding
    size_t hash_len;
    unsigned char *db;

    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        db = (unsigned char *)malloc(em_len - hash_len - 1);
        if (db == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(db, empty_hash_sha224, hash_len);
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        db = (unsigned char *)malloc(em_len - hash_len - 1);
        if (db == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(db, empty_hash_sha256, hash_len);
        break;
    case L2:
        hash_len = SHA384_DIGEST_SIZE;
        db = (unsigned char *)malloc(em_len - hash_len - 1);
        if (db == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(db, empty_hash_sha384, hash_len);
        break;
    case L3:
        hash_len = SHA512_DIGEST_SIZE;
        db = (unsigned char *)malloc(em_len - hash_len - 1);
        if (db == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        memcpy(db, empty_hash_sha512, hash_len);
        break;
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }

    if (m_len > em_len - 2 * hash_len - 2)
    {
        fprintf(stderr, "Message too long\n");
        exit(EXIT_FAILURE);
    }

    memset(db + hash_len, 0x00, em_len - m_len - 2 * hash_len - 2);
    db[em_len - m_len - hash_len - 2] = 0x01;
    memcpy(db + em_len - m_len - hash_len - 1, m, m_len);

    // Generate seed
    unsigned char *seed = (unsigned char *)malloc(hash_len);
    unsigned char *dbMask = (unsigned char *)malloc(em_len - hash_len - 1);
    unsigned char *seedMask = (unsigned char *)malloc(hash_len);
    if (seed == NULL || dbMask == NULL || seedMask == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    gmp_randstate_t state;
    rng_init(state);
    rand_bytes((char *)seed, state, hash_len);

    // Generate mask
    mgf1(dbMask, em_len - hash_len - 1, seed, hash_len, SHA2, sec_level);

    // XOR db and dbMask
    for (unsigned int i = 0; i < em_len - hash_len - 1; i++)
    {
        db[i] ^= dbMask[i];
    }

    // Generate mask
    mgf1(seedMask, hash_len, db, em_len - hash_len - 1, SHA2, sec_level);

    // XOR seed and seedMask
    for (unsigned int i = 0; i < hash_len; i++)
    {
        seed[i] ^= seedMask[i];
    }

    // Concatenate seed and db
    em[0] = 0x00;
    memcpy(em + 1, seed, hash_len);
    memcpy(em + 1 + hash_len, db, em_len - hash_len - 1);

    free(db);
    free(seed);
    free(dbMask);
    free(seedMask);
    gmp_randclear(state);
}

void crypto_encrypt_oaep(mpz_t c, const mpz_t m, const pub_key_t *pk, sec_level_t sec_level)
{
    size_t m_len = count_bytes(m);
    size_t k = count_bytes(pk->n);
    unsigned char *em = malloc(k);
    unsigned char *buf = malloc(m_len);

    // Convert to bytes
    if (em == NULL || buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    bigint_to_bytes(buf, &buf_len, m, BIG);
    eme_oaep_encode(em, k, buf, buf_len, sec_level);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG);

    // Encrypt
    rsaep(c, padded_m, pk);

    mpz_clear(padded_m);
    free(em);
    free(buf);
}

void crypto_decrypt_oaep(mpz_t m, const mpz_t c, const priv_key_t *sk, rsa_algo_t algorithm, sec_level_t sec_level)
{
    size_t k = count_bytes(sk->n);
    size_t c_len = count_bytes(c);
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

    if (c_len != k || k < 2 * hash_len + 2)
    {
        fprintf(stderr, "Invalid ciphertext\n");
        exit(EXIT_FAILURE);
    }

    // Decrypt
    rsadp(m, c, sk, algorithm);

    // Convert to bytes
    unsigned char *buf = malloc(k);
    unsigned char *maskedSeed = malloc(hash_len);
    unsigned char *maskedDB = malloc(k - hash_len - 1);
    unsigned char *seedMask = malloc(hash_len);
    if (buf == NULL || maskedSeed == NULL || maskedDB == NULL || seedMask == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    size_t buf_len;
    buf[0] = 0x00;
    bigint_to_bytes(buf + 1, &buf_len, m, BIG);

    // Check padding
    if (buf[0] != 0x00)
    {
        fprintf(stderr, "Invalid padding\n");
        exit(EXIT_FAILURE);
    }

    // Calculate maskedSeed and maskedDB
    memcpy(maskedSeed, buf + 1, hash_len);
    memcpy(maskedDB, buf + 1 + hash_len, k - hash_len - 1);

    // Generate seedMask
    mgf1(seedMask, hash_len, maskedDB, k - hash_len - 1, SHA2, sec_level);

    // XOR maskedSeed and seedMask
    for (unsigned int i = 0; i < hash_len; i++)
    {
        maskedSeed[i] ^= seedMask[i];
    }

    // Generate dbMask
    unsigned char *dbMask = (unsigned char *)malloc(k - hash_len - 1);
    if (dbMask == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    mgf1(dbMask, k - hash_len - 1, maskedSeed, hash_len, SHA2, sec_level);

    // XOR maskedDB and dbMask
    for (unsigned int i = 0; i < k - hash_len - 1; i++)
    {
        maskedDB[i] ^= dbMask[i];
    }

    // Check padding
    int i = hash_len;
    while (maskedDB[i] != 0x01)
    {
        i++;
    }
    bytes_to_bigint(m, maskedDB + i + 1, k - i - hash_len - 2, BIG);

    free(buf);
    free(maskedSeed);
    free(maskedDB);
    free(seedMask);
    free(dbMask);
}