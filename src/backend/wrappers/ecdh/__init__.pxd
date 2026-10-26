from wrappers.gmp cimport malloc, free, mpz_t, mpz_set, GMPInteger
from wrappers.ecelgamal cimport public_params_t, ecelgamal_setup, ecelgamal_free_params
from wrappers.enums cimport cc_status_t, check

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "ecdh.h":
    cc_status_t ecdh_gen_secret(mpz_t s, const public_params_t *pp)
    cc_status_t ecdh_gen_public(mpz_t p, const mpz_t s, const public_params_t *pp)
    cc_status_t ecdh_compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp)

cdef class ECDH:
    cdef public_params_t pp
    cdef bint has_params

    cpdef bytes gen_secret(self)
    cpdef bytes gen_public(self, bytes secret)
    cpdef bytes compute_shared_secret(self, bytes s, bytes p)