from wrappers.enums cimport sec_level_t
from wrappers.gmp cimport malloc, mpz_t, mpz_set, GMPInteger
from wrappers.enums import SecurityLevel, RSAAlgo, RSAVariant

cdef extern from "conversion.h":
    ctypedef enum byte_order_t:
        NATIVE,
        BIG,
        LITTLE

    void bytes_to_bigint(mpz_t, const unsigned char *, size_t, byte_order_t)
    void bigint_to_bytes(unsigned char *, size_t *, const mpz_t, byte_order_t)
    size_t count_bytes(const mpz_t)

cdef extern from "rsa.h":
    ctypedef enum rsa_algo_t:
        RSA_STANDARD,
        RSA_CRT
    
    ctypedef struct public_params_t:
        int n_bits
        mpz_t e
    
    ctypedef struct pub_key_t:
        mpz_t n
        mpz_t e

    ctypedef struct priv_key_t:
        mpz_t n
        mpz_t p
        mpz_t q
        mpz_t d
        mpz_t dp
        mpz_t dq
        mpz_t q_inv

    void setup(public_params_t *, sec_level_t level)

    void keygen(priv_key_t *, pub_key_t *, public_params_t)

    void rsa_encrypt(mpz_t, const mpz_t, const pub_key_t *)
    void rsa_decrypt(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t)
    void rsa_sign(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t)
    int rsa_verify(const mpz_t, const mpz_t, const pub_key_t *)

    void rsa_encrypt_pkcs1(mpz_t, const mpz_t, const pub_key_t *)
    void rsa_decrypt_pkcs1(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t)
    void rsa_sign_pkcs1(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t, sec_level_t sec_level)
    int rsa_verify_pkcs1(const mpz_t, const mpz_t, const pub_key_t *, sec_level_t sec_level)

    void rsa_encrypt_oaep(mpz_t, const mpz_t, const pub_key_t *, sec_level_t sec_level)
    void rsa_decrypt_oaep(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t, sec_level_t sec_level)
    void rsa_sign_pss(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t, sec_level_t sec_level)
    int rsa_verify_pss(const mpz_t, const mpz_t, const pub_key_t *, sec_level_t sec_level)

cdef class RSA:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef sec_level, variant

    cpdef void keygen(self)
    cpdef bytes encrypt(self, bytes m)
    cpdef bytes decrypt(self, bytes c, algo: RSAAlgo)
    cpdef bytes sign(self, bytes m, algo: RSAAlgo)
    cpdef verify(self, bytes m, bytes s)