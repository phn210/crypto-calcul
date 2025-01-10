from wrappers.enums cimport sec_level_t
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

    void setup(public_params_t *, sec_level_t level)
    void keygen(priv_key_t *, pub_key_t *, const public_params_t *)
    void crypto_encrypt(mpz_t, mpz_t, const mpz_t, const pub_key_t *, const public_params_t *)
    void crypto_decrypt(mpz_t, const mpz_t, const mpz_t, const priv_key_t *, const public_params_t *)
    void crypto_sign(mpz_t, mpz_t, const unsigned char *, size_t, const priv_key_t *, const public_params_t *, sec_level_t)
    int crypto_verify(const mpz_t, const mpz_t, const unsigned char *, size_t, const pub_key_t *, const public_params_t *, sec_level_t)

cdef class ElGamal:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef sec_level

    cpdef void keygen(self)
    cpdef encrypt(self, bytes m)
    cpdef bytes decrypt(self, bytes c1, bytes c2)
    cpdef sign(self, bytes m)
    cpdef verify(self, bytes m, bytes r, bytes s)