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
    mpz_t q;
    mpz_init(q);
    mpz_urandomb(q, state, b);
    if (mpz_divisible_ui_p(q, 2))
        mpz_add_ui(q, q, 1);
    mpz_t *w = (mpz_t *)malloc(k * sizeof(mpz_t));
    if (w == NULL)
    {
        printf("Memory allocation failed\n");
        exit(1);
    }

    mpz_t *small_primes = (mpz_t *)malloc(k * sizeof(mpz_t));
    prepare_small_primes(small_primes, k);

    for (int i = 1; i < k; i++)
    {
        mpz_init(w[i]);
        mpz_mod(w[i], q, small_primes[i]);
    }

    int repeat = 0;
    while (check_w_has_0(w, k) != 0 || repeat)
    {
        repeat = 0;
        for (int i = 1; i < k; i++)
        {
            mpz_add_ui(w[i], w[i], 2);
            mpz_mod(w[i], w[i], small_primes[i]);
        }
        mpz_add_ui(q, q, 2);

        if (!primality_test(q, state, t, test))
        {
            for (int i = 1; i < k; i++)
            {
                mpz_add_ui(w[i], w[i], 2);
                mpz_mod(w[i], w[i], small_primes[i]);
            }
            mpz_add_ui(q, q, 2);
            repeat = 1;
        }
    }
    mpz_set(n, q);
    mpz_clear(q);
    for (int i = 1; i < k; i++)
    {
        mpz_clear(w[i]);
    }
    free(w);
}