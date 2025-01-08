cdef extern from "enum.h":
    ctypedef enum sec_level_t:
        _L0 "L0"
        _L1 "L1"
        _L2 "L2"
        _L3 "L3"

    ctypedef enum hash_func_t:
        _MD5 "MD5"
        _SHA1 "SHA1"
        _SHA2 "SHA2"
        _SHA3 "SHA3"

cdef extern from "prime_test.h":
    ctypedef enum prime_test_t:
        _GMP_TEST "GMP_TEST"
        _FERMAT_TEST "FERMAT_TEST"
        _MILLER_RABIN_TEST "MILLER_RABIN_TEST"

cdef extern from "ec.h":
    ctypedef enum ec_t:
        _WEIERSTRASS "WEIERSTRASS"
        _MONTGOMERY "MONTGOMERY"
        _EDWARDS "EDWARDS"
    
    ctypedef enum weierstrass_curve_t:
        _P224 "P224"
        _P256 "P256"
        _P384 "P384"
        _P521 "P521"
        _P256K1 "P256K1"
        _W25519 "W25519"
        _W448 "W448"

    ctypedef enum montgomery_curve_t:
        _C25519 "C25519"
        _C448 "C448"

    ctypedef enum edwards_curve_t:
        _ED25519 "ED25519"
        _ED448 "ED448"
        _E448 "E448"
    
cdef extern from "des.h":
    ctypedef enum des_mode_t:
        _DES_ENCRYPT "DES_ENCRYPT"
        _DES_DECRYPT "DES_DECRYPT"

cdef extern from "aes.h":
    ctypedef enum AES_MODE:
        _AES_MODE_ECB "AES_MODE_ECB"
        _AES_MODE_CBC "AES_MODE_CBC"
        _AES_MODE_CFB "AES_MODE_CFB"
        _AES_MODE_OFB "AES_MODE_OFB"
        _AES_MODE_CTR "AES_MODE_CTR"
        _AES_MODE_GCM "AES_MODE_GCM"

cdef extern from "rsa.h":
    ctypedef enum rsa_algo_t:
        _RSA_STANDARD "RSA_STANDARD",
        _RSA_CRT "RSA_CRT"