#include "conversion.h"
#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"

void setup(public_params_t *pp, SECURITY_LEVEL level)
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

void encrypt(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    // c = m^e mod n
    mpz_powm(c, m, pk->e, pk->n);
}

void decrypt(mpz_t m, const mpz_t c, const priv_key_t *sk, RSA_ALGORITHM algorithm)
{
    if (algorithm == STANDARD)
    {
        // m = c^d mod n
        mpz_powm(m, c, sk->d, sk->n);
    }
    else if (algorithm == CRT)
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

void encrypt_pkcs1(mpz_t c, const mpz_t m, const pub_key_t *pk)
{
    size_t m_len = count_bytes(m);
    size_t k = count_bytes(pk->n);
    if (m_len > k - 11)
    {
        fprintf(stderr, "Message is too long\n");
        exit(EXIT_FAILURE);
    }

    // Generate padding
    gmp_randstate_t state;
    rng_init(state);
    unsigned char *em = (unsigned char *)malloc(k);
    em[0] = 0x00;
    em[1] = 0x02;
    for (int i = 2; i < k - m_len - 1; i++)
    {
        em[i] = 0x00;
        while (em[i] == 0x00)
        {
            rand_bytes((char *)(em + i), state, 1);
        }
    }
    em[k - m_len - 1] = 0x00;

    size_t buf_len;
    bigint_to_bytes(em + k - m_len, &buf_len, m, BIG_ENDIAN);

    // Convert to MPZ
    mpz_t padded_m;
    mpz_init(padded_m);
    bytes_to_bigint(padded_m, em, k, BIG_ENDIAN);
    // gmp_printf("Padded message: %Zd\n", padded_m);

    // Encrypt
    encrypt(c, padded_m, pk);

    gmp_randclear(state);
    mpz_clear(padded_m);
    free(em);
}

void decrypt_pkcs1(mpz_t m, const mpz_t c, const priv_key_t *sk, RSA_ALGORITHM algorithm)
{
    size_t k = count_bytes(sk->n);
    size_t c_len = count_bytes(c);

    if (c_len != k || k < 11)
    {
        fprintf(stderr, "Invalid ciphertext\n");
        exit(EXIT_FAILURE);
    }

    // Decrypt
    decrypt(m, c, sk, algorithm);
    // gmp_printf("Decrypted: %Zd\n", m);

    // Convert to bytes
    unsigned char *buf = (unsigned char *)malloc(k);
    size_t buf_len;
    buf[0] = 0x00;
    bigint_to_bytes(buf + 1, &buf_len, m, BIG_ENDIAN);

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
    bytes_to_bigint(m, buf + i + 1, k - i - 1, BIG_ENDIAN);
    free(buf);
}