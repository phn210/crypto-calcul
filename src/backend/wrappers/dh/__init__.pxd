from wrappers.gmp cimport malloc, free, mpz_t, mpz_set, GMPInteger
from wrappers.elgamal cimport public_params_t, setup

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "dh.h":
    void gen_secret(mpz_t s, const public_params_t pp)
    void gen_public(mpz_t p, const mpz_t secret, const public_params_t pp)
    void compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t pp)

cdef class DiffieHellman:
    cdef public_params_t pp

    cpdef bytes gen_secret(self)
    cpdef bytes gen_public(self, bytes secret)
    cpdef bytes compute_shared_secret(self, bytes s, bytes p)