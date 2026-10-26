#include "api_internal.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "rng.h"
#include "prime_gen.h"

#define MAX_DIGEST_SIZE 64

static cc_status_t hash_length(cc_hash_t hash, cc_sec_level_t level, size_t *len)
{
    static const size_t lengths[] = {28, 32, 48, 64};
    sec_level_t internal;
    switch (hash)
    {
    case CC_HASH_MD5:
        *len = MD5_DIGEST_SIZE;
        return CC_OK;
    case CC_HASH_SHA1:
        *len = SHA1_DIGEST_SIZE;
        return CC_OK;
    case CC_HASH_SHA2:
    case CC_HASH_SHA3:
        CC_TRY(api_sec_level(level, &internal));
        *len = lengths[internal == L0 ? 0 : internal == L1 ? 1 : internal == L2 ? 2 : 3];
        return CC_OK;
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_hash(cc_hash_t hash, cc_sec_level_t level, const uint8_t *msg, size_t msg_len,
                    uint8_t *digest, size_t *digest_len)
{
    size_t len;
    CC_TRY(hash_length(hash, level, &len));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;
    msg = API_BYTES(msg);

    uint8_t md[MAX_DIGEST_SIZE];
    switch (hash)
    {
    case CC_HASH_MD5:
        md5(msg, msg_len, md, len);
        break;
    case CC_HASH_SHA1:
        sha1(msg, msg_len, md, len);
        break;
    case CC_HASH_SHA2:
        sha2(msg, msg_len, md, len);
        break;
    case CC_HASH_SHA3:
        sha3(msg, msg_len, md, len);
        break;
    }
    return api_output(digest, digest_len, md, len);
}

cc_status_t cc_shake(int security_bits, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len)
{
    if ((security_bits != 128 && security_bits != 256) || (msg == NULL && msg_len > 0) || (out == NULL && out_len > 0))
        return CC_ERR_INVALID_ARG;
    msg = API_BYTES(msg);

    sha3_ctx_t ctx;
    if (security_bits == 128)
        shake128_init(&ctx);
    else
        shake256_init(&ctx);
    shake_update(&ctx, msg, msg_len);
    shake_xof(&ctx);
    shake_out(&ctx, out, out_len);
    return CC_OK;
}

cc_status_t cc_random_bytes(uint8_t *out, size_t len)
{
    if ((out == NULL && len > 0) || len > 0xFFFFFFFFu)
        return CC_ERR_INVALID_ARG;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    rand_bytes((char *)out, state, (unsigned int)len);
    gmp_randclear(state);
    return CC_OK;
}

cc_status_t cc_random_bits(unsigned int bits, uint8_t *out, size_t *out_len)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t r;
    mpz_init(r);
    rand_int_b(r, state, bits);
    cc_status_t status = api_output_mpz(out, out_len, r);

    mpz_clear(r);
    gmp_randclear(state);
    return status;
}

cc_status_t cc_random_below(const uint8_t *m, size_t m_len, uint8_t *out, size_t *out_len)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t bound, r;
    mpz_inits(bound, r, NULL);
    api_input_mpz(bound, m, m_len);
    cc_status_t status = rand_int_m(r, state, bound);
    if (status == CC_OK)
        status = api_output_mpz(out, out_len, r);

    mpz_clears(bound, r, NULL);
    gmp_randclear(state);
    return status;
}

static cc_status_t prime_test(cc_prime_test_t test, prime_test_t *internal)
{
    switch (test)
    {
    case CC_PRIME_TEST_GMP:
        *internal = GMP_TEST;
        return CC_OK;
    case CC_PRIME_TEST_FERMAT:
        *internal = FERMAT_TEST;
        return CC_OK;
    case CC_PRIME_TEST_MILLER_RABIN:
        *internal = MILLER_RABIN_TEST;
        return CC_OK;
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_is_prime(const uint8_t *n, size_t n_len, cc_prime_test_t test, int rounds, int *is_prime)
{
    prime_test_t internal;
    CC_TRY(prime_test(test, &internal));
    if (is_prime == NULL)
        return CC_ERR_INVALID_ARG;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t x;
    mpz_init(x);
    api_input_mpz(x, n, n_len);
    cc_status_t status = primality_test(x, state, rounds, internal, is_prime);

    mpz_clear(x);
    gmp_randclear(state);
    return status;
}

cc_status_t cc_prime_bits(unsigned int bits, int small_primes, cc_prime_test_t test, int rounds,
                          uint8_t *out, size_t *out_len)
{
    prime_test_t internal;
    CC_TRY(prime_test(test, &internal));
    if (bits > 1u << 20)
        return CC_ERR_INVALID_ARG;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t p;
    mpz_init(p);
    cc_status_t status = gen_prime_b(p, state, (int)bits, small_primes, rounds, internal);
    if (status == CC_OK)
        status = api_output_mpz(out, out_len, p);

    mpz_clear(p);
    gmp_randclear(state);
    return status;
}

cc_status_t cc_prime_below(const uint8_t *m, size_t m_len, int small_primes, cc_prime_test_t test, int rounds,
                           uint8_t *out, size_t *out_len)
{
    prime_test_t internal;
    CC_TRY(prime_test(test, &internal));

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t bound, p;
    mpz_inits(bound, p, NULL);
    api_input_mpz(bound, m, m_len);
    cc_status_t status = gen_prime_m(p, state, bound, small_primes, rounds, internal);
    if (status == CC_OK)
        status = api_output_mpz(out, out_len, p);

    mpz_clears(bound, p, NULL);
    gmp_randclear(state);
    return status;
}
