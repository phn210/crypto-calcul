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
    default:
        fprintf(stderr, "Invalid security level\n");
        exit(EXIT_FAILURE);
    }
}

void keygen(priv_key *sk, pub_key *pk, public_params_t pp)
{
    gmp_randstate_t state;
    rng_init(state);

    // Initialize all MPZ variables
    mpz_inits(sk->p, sk->q, sk->d, pk->n, pk->e, NULL);

    // Set public exponent
    mpz_set(pk->e, pp.e);

    mpz_t p_1, q_1, phi_n, gcd;
    mpz_inits(p_1, q_1, phi_n, gcd, NULL);

    // Generate two distinct primes of equal size
    while (1)
    {
        // Generate first prime
        gen_prime_b(sk->p, state, pp.n_bits / 2, 100, 25, GMP_TEST);

        // Generate second prime
        do
        {
            gen_prime_b(sk->q, state, pp.n_bits / 2, 100, 25, GMP_TEST);
        } while (mpz_cmp(sk->p, sk->q) == 0);

        // Compute n = p * q
        mpz_mul(pk->n, sk->p, sk->q);

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
            break;
        }
    }

    // Clear temporary variables
    mpz_clears(p_1, q_1, phi_n, gcd, NULL);
    gmp_randclear(state);
}

void encrypt(mpz_t c, const mpz_t m, const pub_key pk)
{
    // c = m^e mod n
    mpz_powm(c, m, pk.e, pk.n);
}

void decrypt(mpz_t m, const mpz_t c, const priv_key sk, const pub_key pk)
{
    // Chinese Remainder Theorem (CRT) optimization for decryption
    mpz_t m1, m2, h, temp;
    mpz_inits(m1, m2, h, temp, NULL);

    // m1 = c^(d mod (p-1)) mod p
    mpz_sub_ui(temp, sk.p, 1);
    mpz_mod(temp, sk.d, temp);
    mpz_powm(m1, c, temp, sk.p);

    // m2 = c^(d mod (q-1)) mod q
    mpz_sub_ui(temp, sk.q, 1);
    mpz_mod(temp, sk.d, temp);
    mpz_powm(m2, c, temp, sk.q);

    // h = q^(-1) * (m1 - m2) mod p
    mpz_sub(temp, m1, m2);
    mpz_invert(h, sk.q, sk.p);
    mpz_mul(h, h, temp);
    mpz_mod(h, h, sk.p);

    // m = m2 + h * q
    mpz_mul(temp, h, sk.q);
    mpz_add(m, m2, temp);

    mpz_clears(m1, m2, h, temp, NULL);
}

void keygen_crt(priv_key_crt *sk, pub_key *pk, public_params_t pp)
{
    gmp_randstate_t state;
    rng_init(state);

    // Initialize all MPZ variables
    mpz_inits(sk->p, sk->q, sk->d, sk->dp, sk->dq, sk->qinv, pk->n, pk->e, NULL);

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
        mpz_mul(pk->n, sk->p, sk->q);

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
            mpz_mod(sk->dp, sk->d, p_1);        // dp = d mod (p-1)
            mpz_mod(sk->dq, sk->d, q_1);        // dq = d mod (q-1)
            mpz_invert(sk->qinv, sk->q, sk->p); // qinv = q^(-1) mod p
            break;
        }
    }

    // Clear temporary variables
    mpz_clears(p_1, q_1, phi_n, gcd, NULL);
    gmp_randclear(state);
}

void encrypt_crt(mpz_t c, const mpz_t m, const pub_key pk)
{
    // Standard RSA encryption: c = m^e mod n
    mpz_powm(c, m, pk.e, pk.n);
}

void decrypt_crt(mpz_t m, const mpz_t c, const priv_key_crt sk, const pub_key pk)
{
    // Chinese Remainder Theorem (CRT) optimization for decryption
    mpz_t m1, m2, h;
    mpz_inits(m1, m2, h, NULL);

    // m1 = c^dp mod p
    mpz_powm(m1, c, sk.dp, sk.p);

    // m2 = c^dq mod q
    mpz_powm(m2, c, sk.dq, sk.q);

    // h = qinv * (m1 - m2) mod p
    mpz_sub(h, m1, m2);
    if (mpz_sgn(h) < 0)
    {
        mpz_add(h, h, sk.p);
    }
    mpz_mul(h, sk.qinv, h);
    mpz_mod(h, h, sk.p);

    // m = m2 + h * q
    mpz_mul(h, h, sk.q);
    mpz_add(m, m2, h);

    mpz_clears(m1, m2, h, NULL);
}