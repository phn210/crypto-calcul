#include "conversion.h"
#include "rsacrt_sig.h"
#include "prime_gen.h"
#include "rng.h"

void keygen(priv_key *sk, pub_key *pk) {
    gmp_randstate_t state;
    rng_init(state);
    
    // Initialize all MPZ variables
    mpz_inits(sk->p, sk->q, sk->d, sk->dp, sk->dq, sk->qinv, pk->n, pk->e, NULL);
    
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
            
            // Compute CRT components
            mpz_mod(sk->dp, sk->d, p_1);    // dp = d mod (p-1)
            mpz_mod(sk->dq, sk->d, q_1);    // dq = d mod (q-1)
            mpz_invert(sk->qinv, sk->q, sk->p);  // qinv = q^(-1) mod p
            break;
        }
    }
    
    mpz_clears(p_1, q_1, phi_n, gcd, NULL);
    gmp_randclear(state);
}

void sign(mpz_t s, const mpz_t m, const priv_key sk, const pub_key pk) {
    // Chinese Remainder Theorem (CRT) optimization for signing
    mpz_t s1, s2, h;
    mpz_inits(s1, s2, h, NULL);
    
    // s1 = m^dp mod p
    mpz_powm(s1, m, sk.dp, sk.p);
    
    // s2 = m^dq mod q
    mpz_powm(s2, m, sk.dq, sk.q);
    
    // h = qinv * (s1 - s2) mod p
    mpz_sub(h, s1, s2);
    if (mpz_sgn(h) < 0) {
        mpz_add(h, h, sk.p);
    }
    mpz_mul(h, sk.qinv, h);
    mpz_mod(h, h, sk.p);
    
    // s = s2 + h * q
    mpz_mul(h, h, sk.q);
    mpz_add(s, s2, h);
    
    mpz_clears(s1, s2, h, NULL);
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