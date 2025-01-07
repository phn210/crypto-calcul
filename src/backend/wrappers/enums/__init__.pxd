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