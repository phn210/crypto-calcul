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

    cc_status_t rsa_setup(public_params_t *, sec_level_t level)
    cc_status_t rsa_keygen(priv_key_t *, pub_key_t *, const public_params_t *)
    void rsa_free_params(public_params_t *)
    void rsa_free_keys(priv_key_t *, pub_key_t *)
    size_t rsa_modulus_size(const mpz_t)

    cc_status_t rsa_encrypt(mpz_t, const mpz_t, const pub_key_t *)
    cc_status_t rsa_decrypt(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t)
    cc_status_t rsa_sign(mpz_t, const mpz_t, const priv_key_t *, rsa_algo_t)
    cc_status_t rsa_verify(const mpz_t, const mpz_t, const pub_key_t *)

    cc_status_t rsa_encrypt_pkcs1(unsigned char *, const unsigned char *, size_t, const pub_key_t *)
    cc_status_t rsa_decrypt_pkcs1(unsigned char *, size_t *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t)
    cc_status_t rsa_sign_pkcs1(unsigned char *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t, sec_level_t)
    cc_status_t rsa_verify_pkcs1(const unsigned char *, size_t, const unsigned char *, size_t, const pub_key_t *, sec_level_t)

    cc_status_t rsa_encrypt_oaep(unsigned char *, const unsigned char *, size_t, const pub_key_t *, sec_level_t)
    cc_status_t rsa_decrypt_oaep(unsigned char *, size_t *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t, sec_level_t)
    cc_status_t rsa_sign_pss(unsigned char *, const unsigned char *, size_t, const priv_key_t *, rsa_algo_t, sec_level_t)
    cc_status_t rsa_verify_pss(const unsigned char *, size_t, const unsigned char *, size_t, const pub_key_t *, sec_level_t)

cdef class RSA:
    cdef public_params_t pp
    cdef priv_key_t sk
    cdef pub_key_t pk
    cdef sec_level, variant
    cdef bint has_params, has_key

    cpdef void keygen(self)
    cpdef bytes encrypt(self, bytes m)
    cpdef bytes decrypt(self, bytes c, algo)
    cpdef bytes sign(self, bytes m, algo)
    cpdef verify(self, bytes m, bytes s)
