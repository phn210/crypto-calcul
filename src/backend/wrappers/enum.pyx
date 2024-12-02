from enum import Enum

cdef extern from "parameters.h":
    # SECURITY_LEVEL
    int L0
    int L1
    int L2
    int L3

    # PRIMALITY_TEST
    int GMP_TEST
    int FERMAT_TEST
    int MILLER_RABIN_TEST

    # HASH_FUNCTION
    int MD5
    int SHA1
    int SHA2
    int SHA3

    # EC
    int WEIERSTRASS
    int MONTGOMERY
    int EDWARDS

    # WEIERSTRASS_CURVE
    int P224
    int P256
    int P384
    int P521
    int P256K1
    int W25519
    int W448

    # MONTGOMERY_CURVE
    int C25519
    int C448

    # EDWARDS_CURVE
    int ED25519
    int ED448
    int E448


class SecurityLevel(Enum):
    _L0 = int(L0)
    _L1 = int(L1)
    _L2 = int(L2)
    _L3 = int(L3)

class PrimalityTest(Enum):
    _GMP_TEST = int(GMP_TEST)
    _FERMAT_TEST = int(FERMAT_TEST)
    _MILLER_RABIN_TEST = int(MILLER_RABIN_TEST)

class HashFunction(Enum):
    _MD5 = int(MD5)
    _SHA1 = int(SHA1)
    _SHA2 = int(SHA2)
    _SHA3 = int(SHA3)

class EC(Enum):
    _WEIERSTRASS = int(WEIERSTRASS)
    _MONTGOMERY = int(MONTGOMERY)
    _EDWARDS = int(EDWARDS)

class WeierstrassCurve(Enum):
    _P224 = int(P224)
    _P256 = int(P256)
    _P384 = int(P384)
    _P521 = int(P521)
    _P256K1 = int(P256K1)
    _W25519 = int(W25519)
    _W448 = int(W448)

class MontgomeryCurve(Enum):
    _25519 = int(C25519)
    _C448 = int(C448)

class EdwardsCurve(Enum):
    _ED25519 = int(ED25519)
    _ED448 = int(ED448)
    _E448 = int(E448)