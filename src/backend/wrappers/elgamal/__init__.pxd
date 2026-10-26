from wrappers.enums cimport sec_level_t, cc_status_t, check, check_verify
from wrappers.gmp cimport malloc, free, mpz_t, mpz_set, GMPInteger

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "elgamal.h":
    ctypedef struct public_params_t:
        int p_bits
        mpz_t p
        mpz_t g

    ctypedef struct pub_key_t:
        mpz_t y

    ctypedef struct priv_key_t:
        mpz_t x

    cc_status_t elgamal_setup(public_params_t *, sec_level_t level)
    cc_status_t elgamal_keygen(priv_key_t *, pub_key_t *, const public_params_t *)
    void elgamal_free_params(public_params_t *)
    void elgamal_free_keys(priv_key_t *, pub_key_t *)
    cc_status_t elgamal_encrypt(mpz_t, mpz_t, const mpz_t, const pub_key_t *, const public_params_t *)
    cc_status_t elgamal_decrypt(mpz_t, const mpz_t, const mpz_t, const priv_key_t *, const public_params_t *)
    cc_status_t elgamal_sign(mpz_t, mpz_t, const unsigned char *, size_t, const priv_key_t *, const public_params_t *, sec_level_t)
    cc_status_t elgamal_verify(const mpz_t, const mpz_t, const unsigned char *, size_t, const pub_key_t *, const public_params_t *, sec_level_t)

cdef class ElGamal:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef sec_level
    cdef bint has_params, has_key

    cpdef void keygen(self)
    cpdef encrypt(self, bytes m)
    cpdef bytes decrypt(self, bytes c1, bytes c2)
    cpdef sign(self, bytes m)
    cpdef verify(self, bytes m, bytes r, bytes s)