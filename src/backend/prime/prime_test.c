#include "prime_test.h"

int test_fermat_base(mpz_t a, mpz_t n)
{
    mpz_t check;
    mpz_init(check);
    mpz_sub_ui(check, n, 1);
    mpz_powm(check, a, check, n);
    int res = mpz_cmp_ui(check, 1) == 0;
    mpz_clear(check);
    return res;
}

int test_fermat(mpz_t n, gmp_randstate_t state, int t)
{
    int check = 1;
    while (t > 0 && check)
    {
        mpz_t a;
        mpz_init(a);
        mpz_sub_ui(a, n, 3);       // a = n - 3
        mpz_urandomm(a, state, a); // a = random([0, n - 3))
        mpz_add_ui(a, a, 2);       // a = a + 2
        check = test_fermat_base(a, n);
        mpz_clear(a);
        t--;
    }
    return check;
}

int test_miller_rabin_base(mpz_t a, mpz_t n, mpz_t n1, mpz_t r, int s)
{
    mpz_t y;
    mpz_init(y);
    mpz_powm(y, a, r, n);

    if (mpz_cmp_ui(y, 1) == 0 || mpz_cmp(y, n1) == 0)
    {
        mpz_clear(y);
        return 1;
    }
    else
    {
        for (int j = 1; j < s && mpz_cmp(y, n1) != 0; j++)
        {
            mpz_powm_ui(y, y, 2, n);

            if (mpz_cmp_ui(y, 1) == 0)
            {
                mpz_clear(y);
                return 0;
            }
        }
        if (mpz_cmp(y, n1) != 0)
        {
            mpz_clear(y);
            return 0;
        }
    }
    mpz_clear(y);
    return 1;
}

int test_miller_rabin(mpz_t n, gmp_randstate_t state, int t)
{
    if (mpz_divisible_2exp_p(n, 1))
        return 0;
    int s = 0;
    mpz_t r, n1;
    mpz_inits(r, n1, NULL);
    mpz_sub_ui(n1, n, 1);
    while (mpz_divisible_2exp_p(n1, s + 1))
        s++;
    mpz_cdiv_q_2exp(r, n1, s);

    for (int i = 0; i < t; i++)
    {
        mpz_t a;
        mpz_init(a);
        mpz_sub_ui(a, n, 3);       // a = n - 3
        mpz_urandomm(a, state, a); // a = random([0, n - 3))
        mpz_add_ui(a, a, 2);       // a = a + 2
        if (!test_miller_rabin_base(a, n, n1, r, s))
        {
            mpz_clears(a, r, n1, NULL);
            return 0;
        }
        mpz_clear(a);
    }
    mpz_clears(r, n1, NULL);
    return 1;
}

int primality_test(mpz_t n, gmp_randstate_t state, int t, prime_test_t test)
{
    if (mpz_cmp_ui(n, 2) < 0)
        return 0;
    if (mpz_cmp_ui(n, 2) == 0)
        return 1;
    if (mpz_divisible_2exp_p(n, 1))
        return 0;
    if (test == FERMAT_TEST)
        return test_fermat(n, state, t);
    if (test == MILLER_RABIN_TEST)
        return test_miller_rabin(n, state, t);
    if (test == GMP_TEST)
        return mpz_probab_prime_p(n, t);

    printf("Unknown primality test\n");
    exit(1);
}