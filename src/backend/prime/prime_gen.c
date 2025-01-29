#include "prime_gen.h"
#include "rng.h"

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

void gen_prime_b(mpz_t n, gmp_randstate_t state, int b, int k, int t, prime_test_t test)
{
    mpz_t q, tmp;
    mpz_inits(q, tmp, NULL);
    while (mpz_tstbit(q, 0) == 0)
    {
        mpz_urandomb(q, state, b - 1);
    }
    mpz_ui_pow_ui(tmp, 2, b - 1);
    mpz_add(q, q, tmp);
    if (mpz_divisible_ui_p(q, 2))
        mpz_add_ui(q, q, 1);

    mpz_t *small_primes = (mpz_t *)malloc(k * sizeof(mpz_t));
    if (small_primes == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
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
    mpz_clears(q, tmp, NULL);
    for (int i = 0; i < k; i++)
    {
        mpz_clear(small_primes[i]);
    }
    free(small_primes);
}

void gen_prime_m(mpz_t n, gmp_randstate_t state, mpz_t m, int k, int t, prime_test_t test)
{
    mpz_t q, tmp;
    mpz_inits(q, tmp, NULL);
    rand_int_m(q, state, m);
    if (mpz_cmp_ui(q, 2) == 0)
    {
        mpz_set(n, q);
        mpz_clears(q, tmp, NULL);
        return;
    }
    if (mpz_divisible_ui_p(q, 2))
        mpz_add_ui(q, q, 1);

    mpz_t *small_primes = (mpz_t *)malloc(k * sizeof(mpz_t));
    if (small_primes == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    prepare_small_primes(small_primes, k);

    int j = 1;
    while (j < k)
    {
        if (mpz_cmp(q, m) >= 0)
        {
            fprintf(stderr, "Generated number is greater than m\n");
            mpz_clears(q, tmp, NULL);
            for (int i = 0; i < k; i++)
            {
                mpz_clear(small_primes[i]);
            }
            free(small_primes);
            exit(EXIT_FAILURE);
        }
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
    mpz_clears(q, tmp, NULL);
    for (int i = 0; i < k; i++)
    {
        mpz_clear(small_primes[i]);
    }
    free(small_primes);
}