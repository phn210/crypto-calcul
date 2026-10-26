#include "prime_gen.h"
#include "rng.h"

typedef struct small_primes
{
    mpz_t *values;
    int count;
} small_primes_t;

static cc_status_t small_primes_init(small_primes_t *sp, int k)
{
    sp->values = (mpz_t *)malloc(k * sizeof(mpz_t));
    if (sp->values == NULL)
        return CC_ERR_NOMEM;
    sp->count = k;

    mpz_init_set_ui(sp->values[0], 2);
    for (int i = 1; i < k; i++)
    {
        mpz_init(sp->values[i]);
        mpz_nextprime(sp->values[i], sp->values[i - 1]);
    }
    return CC_OK;
}

static void small_primes_clear(small_primes_t *sp)
{
    for (int i = 0; i < sp->count; i++)
        mpz_clear(sp->values[i]);
    free(sp->values);
}

// Trial division by the odd small primes, then the primality test
static cc_status_t is_probable_prime(const mpz_t q, const small_primes_t *sp, gmp_randstate_t state, int t, prime_test_t test, int *is_prime)
{
    for (int j = 1; j < sp->count; j++)
    {
        if (mpz_cmp(q, sp->values[j]) == 0)
        {
            *is_prime = 1;
            return CC_OK;
        }
        if (mpz_divisible_p(q, sp->values[j]))
        {
            *is_prime = 0;
            return CC_OK;
        }
    }
    return primality_test(q, state, t, test, is_prime);
}

static cc_status_t check_params(int k, int t, prime_test_t test)
{
    if (k < 1 || t < 1 || (test != GMP_TEST && test != FERMAT_TEST && test != MILLER_RABIN_TEST))
        return CC_ERR_INVALID_ARG;
    return CC_OK;
}

cc_status_t gen_prime_b(mpz_t n, gmp_randstate_t state, int b, int k, int t, prime_test_t test)
{
    if (b < 2)
        return CC_ERR_INVALID_ARG;
    CC_TRY(check_params(k, t, test));

    small_primes_t sp;
    CC_TRY(small_primes_init(&sp, k));

    // Odd candidate with the top bit set
    mpz_t q;
    mpz_init(q);
    mpz_urandomb(q, state, b - 1);
    mpz_setbit(q, b - 1);
    mpz_setbit(q, 0);

    cc_status_t status;
    int is_prime = 0;
    while ((status = is_probable_prime(q, &sp, state, t, test, &is_prime)) == CC_OK && !is_prime)
        mpz_add_ui(q, q, 2);

    if (status == CC_OK)
        mpz_set(n, q);
    mpz_clear(q);
    small_primes_clear(&sp);
    return status;
}

cc_status_t gen_prime_m(mpz_t n, gmp_randstate_t state, const mpz_t m, int k, int t, prime_test_t test)
{
    if (mpz_cmp_ui(m, 2) <= 0)
        return CC_ERR_INVALID_ARG;
    CC_TRY(check_params(k, t, test));

    small_primes_t sp;
    CC_TRY(small_primes_init(&sp, k));

    mpz_t q;
    mpz_init(q);

    cc_status_t status = CC_OK;
    int is_prime = 0;
    while (status == CC_OK && !is_prime)
    {
        // Random start, then walk up through odd numbers; restart if we pass m
        status = rand_int_m(q, state, m);
        if (status != CC_OK)
            break;
        if (mpz_cmp_ui(q, 2) == 0)
        {
            is_prime = 1;
            break;
        }
        mpz_setbit(q, 0);
        while (mpz_cmp(q, m) < 0)
        {
            status = is_probable_prime(q, &sp, state, t, test, &is_prime);
            if (status != CC_OK || is_prime)
                break;
            mpz_add_ui(q, q, 2);
        }
    }

    if (status == CC_OK)
        mpz_set(n, q);
    mpz_clear(q);
    small_primes_clear(&sp);
    return status;
}
