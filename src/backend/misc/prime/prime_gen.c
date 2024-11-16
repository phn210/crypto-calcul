#include "prime_gen.h"
#include "prime_test.h"

void prepare_small_primes(mpz_t *small_primes, int k)
{
    mpz_init_set_ui(small_primes[0], 2);
    for (int i = 1; i < k; i++)
    {
        mpz_init(small_primes[i]);
        mpz_nextprime(small_primes[i], small_primes[i - 1]);
    }
}

int check_w_has_0(mpz_t *w, int k)
{
    for (int i = 1; i < k; i++)
    {
        if (mpz_cmp_ui(w[i], 0) == 0)
            return i;
    }
    return 0;
}

void gen_prime(mpz_t n, gmp_randstate_t state, int b, int k, int t, PRIMALITY_TEST test)
{
    mpz_t q, tmp;
    mpz_inits(q, tmp, NULL);
    mpz_urandomb(q, state, b - 1);
    mpz_ui_pow_ui(tmp, 2, b - 1);
    mpz_add(q, q, tmp);
    if (mpz_divisible_ui_p(q, 2))
        mpz_add_ui(q, q, 1);

    mpz_t *small_primes = (mpz_t *)malloc(k * sizeof(mpz_t));
    prepare_small_primes(small_primes, k);

    int j = 1;
    while (j < k)
    {
        if (mpz_divisible_p(q, small_primes[j]))
        {
            mpz_add_ui(q, q, 2);
            j = 1;
            continue;
        }
        else
            j++;
        if (j == k && !primality_test(q, state, t, test))
        {
            mpz_add_ui(q, q, 2);
            j = 1;
        }
    }
    mpz_set(n, q);
    mpz_clear(q);
}