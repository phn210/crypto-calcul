from wrappers.enums cimport sec_level_t, hash_func_t, cc_status_t, check, check_verify
from wrappers.gmp cimport malloc, free, mpz_t, mpz_set, GMPInteger

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "dsa.h":
    ctypedef struct public_params_t:
        int p_bits
        int q_bits
        mpz_t p
        mpz_t q
        mpz_t g
    
    ctypedef struct pub_key_t:
        mpz_t y

    ctypedef struct priv_key_t:
        mpz_t x

    cc_status_t dsa_setup(public_params_t *pp, sec_level_t level, hash_func_t)
    cc_status_t dsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
    void dsa_free_params(public_params_t *)
    void dsa_free_keys(priv_key_t *, pub_key_t *)
    cc_status_t dsa_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t, const priv_key_t *sk, const public_params_t *pp)
    cc_status_t dsa_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t, const pub_key_t *pk, const public_params_t *pp)

cdef class DSA:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef bint has_params, has_key

    cpdef void keygen(self)
    cpdef sign(self, bytes m)
    cpdef verify(self, bytes m, bytes r, bytes s)
