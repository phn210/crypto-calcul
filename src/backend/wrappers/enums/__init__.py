import cython
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

class CryptoError(Exception):
    """Error reported by the C library; status is its cc_status_t code."""
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status

def check(status):
    if status != CC_OK:
        raise CryptoError(status, cc_strerror(status).decode())
    return 0

def check_verify(status):
    if status == CC_ERR_VERIFY:
        return 0
    check(status)
    return 1
