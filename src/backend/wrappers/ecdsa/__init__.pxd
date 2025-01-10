from wrappers.enums cimport hash_func_t
from wrappers.ec cimport ec_t, curve_t, point_t, copy_point, EC, ECP
from wrappers.gmp cimport malloc, free, mpz_t, mpz_set, GMPInteger

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "ecdsa.h":
    ctypedef struct public_params_t:
        curve_t curve

    ctypedef struct pub_key_t:
        point_t Q

    ctypedef struct priv_key_t:
        mpz_t d

    void setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id)
    void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
    void crypto_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
    int crypto_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)

cdef class ECDSA:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef EC curve

    cpdef void keygen(self)
    cpdef sign(self, bytes m, hash_func)
    cpdef verify(self, bytes m, bytes r, bytes s, hash_func)