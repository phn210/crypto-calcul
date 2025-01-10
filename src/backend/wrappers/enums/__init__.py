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