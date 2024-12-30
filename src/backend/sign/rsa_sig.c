#include "rsa.h"
#include "prime_gen.h"
#include "rng.h"

void sign(mpz_t s, const mpz_t m, const priv_key sk, const pub_key pk)
{
    // s = m^d mod n
    mpz_powm(s, m, sk.d, pk.n);
}

int verify(const mpz_t m, const mpz_t s, const pub_key pk)
{
    // Verify: m ?= s^e mod n
    mpz_t m_check;
    mpz_init(m_check);
    mpz_powm(m_check, s, pk.e, pk.n);

    int result = (mpz_cmp(m_check, m) == 0);
    mpz_clear(m_check);
    return result;
}

void sign_crt(mpz_t s, const mpz_t m, const priv_key_crt sk, const pub_key pk)
{
    // Chinese Remainder Theorem (CRT) optimization for signing
    mpz_t s1, s2, h;
    mpz_inits(s1, s2, h, NULL);

    // s1 = m^dp mod p
    mpz_powm(s1, m, sk.dp, sk.p);

    // s2 = m^dq mod q
    mpz_powm(s2, m, sk.dq, sk.q);

    // h = qinv * (s1 - s2) mod p
    mpz_sub(h, s1, s2);
    if (mpz_sgn(h) < 0)
    {
        mpz_add(h, h, sk.p);
    }
    mpz_mul(h, sk.qinv, h);
    mpz_mod(h, h, sk.p);

    // s = s2 + h * q
    mpz_mul(h, h, sk.q);
    mpz_add(s, s2, h);

    mpz_clears(s1, s2, h, NULL);
}

int verify_crt(const mpz_t m, const mpz_t s, const pub_key pk)
{
    // Verify: m ?= s^e mod n
    mpz_t m_check;
    mpz_init(m_check);
    mpz_powm(m_check, s, pk.e, pk.n);

    int result = (mpz_cmp(m_check, m) == 0);
    mpz_clear(m_check);
    return result;
}