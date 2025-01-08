from enum import Enum

class SecurityLevel(Enum):
    L0 = _L0
    L1 = _L1
    L2 = _L2
    L3 = _L3

class HashFunction(Enum):
    MD5 = _MD5
    SHA1 = _SHA1
    SHA2 = _SHA2
    SHA3 = _SHA3

class PrimalityTest(Enum):
    GMP_TEST = _GMP_TEST
    FERMAT_TEST = _FERMAT_TEST
    MILLER_RABIN_TEST = _MILLER_RABIN_TEST

class EC(Enum):
    WEIERSTRASS = _WEIERSTRASS
    MONTGOMERY = _MONTGOMERY
    EDWARDS = _EDWARDS

class WeierstrassCurve(Enum):
    P224 = _P224
    P256 = _P256
    P384 = _P384
    P521 = _P521
    P256K1 = _P256K1
    W25519 = _W25519
    W448 = _W448

class MontgomeryCurve(Enum):
    C25519 = _C25519
    C448 = _C448

class EdwardsCurve(Enum):
    ED25519 = _ED25519
    ED448 = _ED448
    E448 = _E448

class DESMode(Enum):
    DES_ENCRYPT = _DES_ENCRYPT
    DES_DECRYPT = _DES_DECRYPT

class AESMode(Enum):
    AES_MODE_ECB = _AES_MODE_ECB
    AES_MODE_CBC = _AES_MODE_CBC
    AES_MODE_CFB = _AES_MODE_CFB
    AES_MODE_OFB = _AES_MODE_OFB
    AES_MODE_CTR = _AES_MODE_CTR
    AES_MODE_GCM = _AES_MODE_GCM