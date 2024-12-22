#include "conversion.h"
#include "rsa_sig.h"
#include "prime_gen.h"
#include "rng.h"

void keygen(priv_key *sk, pub_key *pk) {
    gmp_randstate_t state;
    rng_init(state);
    
    // Initialize all MPZ variables
    mpz_inits(sk->p, sk->q, sk->d, pk->n, pk->e, NULL);
    
    // Set public exponent
    mpz_set_str(pk->e, E, 10);
    
    mpz_t p_1, q_1, phi_n, gcd;
    mpz_inits(p_1, q_1, phi_n, gcd, NULL);
    
    // Generate two distinct primes of equal size
    while (1) {
        gen_prime_b(sk->p, state, N_BITS/2, 100, 25, MILLER_RABIN_TEST);
        
        do {
            gen_prime_b(sk->q, state, N_BITS/2, 100, 25, MILLER_RABIN_TEST);
        } while (mpz_cmp(sk->p, sk->q) == 0);
        
        // Compute n = p * q
        mpz_mul(pk->n, sk->p, sk->q);
        
        // Compute φ(n) = (p-1)(q-1)
        mpz_sub_ui(p_1, sk->p, 1);
        mpz_sub_ui(q_1, sk->q, 1);
        mpz_mul(phi_n, p_1, q_1);
        
        // Check if e and φ(n) are coprime
        mpz_gcd(gcd, pk->e, phi_n);
        if (mpz_cmp_ui(gcd, 1) == 0) {
            // Compute private exponent d = e^(-1) mod φ(n)
            mpz_invert(sk->d, pk->e, phi_n);
            break;
        }
    }
    
    mpz_clears(p_1, q_1, phi_n, gcd, NULL);
    gmp_randclear(state);
}

void sign(mpz_t s, const mpz_t m, const priv_key sk, const pub_key pk) {
    // s = m^d mod n
    mpz_powm(s, m, sk.d, pk.n);
}

int verify(const mpz_t m, const mpz_t s, const pub_key pk) {
    // Verify: m ?= s^e mod n
    mpz_t m_check;
    mpz_init(m_check);
    mpz_powm(m_check, s, pk.e, pk.n);
    
    int result = (mpz_cmp(m_check, m) == 0);
    mpz_clear(m_check);
    return result;
}