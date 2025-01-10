from wrappers.enums cimport sec_level_t, hash_func_t
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

    void setup(public_params_t *pp, sec_level_t level, hash_func_t)
    void keygen(priv_key_t *sk, pub_key_t *pk, public_params_t pp)
    void crypto_sign(mpz_t r, mpz_t s, const unsigned char *m, int, priv_key_t sk, public_params_t pp)
    char crypto_verify(const mpz_t r, const mpz_t s, const unsigned char *m, int, pub_key_t pk, public_params_t pp)

cdef class DSA:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk

    cpdef void keygen(self)
    cpdef sign(self, bytes m)
    cpdef verify(self, bytes m, bytes r, bytes s)
