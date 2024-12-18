cdef extern from "parameters.h":
    # SECURITY_LEVEL
    cdef const int _L0 "L0"
    cdef const int _L1 "L1"
    cdef const int _L2 "L2"
    cdef const int _L3 "L3"

    # PRIMALITY_TEST
    cdef const int _GMP_TEST "GMP_TEST"
    cdef const int _FERMAT_TEST "FERMAT_TEST"
    cdef const int _MILLER_RABIN_TEST "MILLER_RABIN_TEST"

    # HASH_FUNCTION
    cdef const int _MD5 "MD5"
    cdef const int _SHA1 "SHA1"
    cdef const int _SHA2 "SHA2"
    cdef const int _SHA3 "SHA3"

    # EC
    cdef const int _WEIERSTRASS "WEIERSTRASS"
    cdef const int _MONTGOMERY "MONTGOMERY"
    cdef const int _EDWARDS "EDWARDS"

    # WEIERSTRASS_CURVE
    cdef const int _P224 "P224"
    cdef const int _P256 "P256"
    cdef const int _P384 "P384"
    cdef const int _P521 "P521"
    cdef const int _P256K1 "P256K1"
    cdef const int _W25519 "W25519"
    cdef const int _W448 "W448"

    # MONTGOMERY_CURVE
    cdef const int _C25519 "C25519"
    cdef const int _C448 "C448"

    # EDWARDS_CURVE
    cdef const int _ED25519 "ED25519"
    cdef const int _ED448 "ED448"
    cdef const int _E448 "E448"


cpdef enum SecurityLevel:
    L0 = _L0
    L1 = _L1
    L2 = _L2
    L3 = _L3

cpdef enum PrimalityTest:
    GMP_TEST = _GMP_TEST
    FERMAT_TEST = _FERMAT_TEST
    MILLER_RABIN_TEST = _MILLER_RABIN_TEST

cpdef enum HashFunction:
    MD5 = _MD5
    SHA1 = _SHA1
    SHA2 = _SHA2
    SHA3 = _SHA3

cpdef enum EC:
    WEIERSTRASS = _WEIERSTRASS
    MONTGOMERY = _MONTGOMERY
    EDWARDS = _EDWARDS

cpdef enum WeierstrassCurve:
    P224 = _P224
    P256 = _P256
    P384 = _P384
    P521 = _P521
    P256K1 = _P256K1
    W25519 = _W25519
    W448 = _W448

cpdef enum MontgomeryCurve:
    C25519 = _C25519
    C448 = _C448

cpdef enum EdwardsCurve:
    ED25519 = _ED25519
    ED448 = _ED448
    E448 = _E448