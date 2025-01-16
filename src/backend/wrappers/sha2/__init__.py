import cython
from wrappers.enums import SecurityLevel

@cython.cclass
class SHA2:
    def __init__(self, sec_level: SecurityLevel):
        if sec_level == SecurityLevel.L0:
            self.md_len = 28
        elif sec_level == SecurityLevel.L1:
            self.md_len = 32
        elif sec_level == SecurityLevel.L2:
            self.md_len = 48
        elif sec_level == SecurityLevel.L3:
            self.md_len = 64
        else:
            raise ValueError("Invalid Security Level")

    @cython.ccall
    def hash(self, m: bytes) -> bytes:
        md = cython.cast(cython.p_char, malloc(self.md_len))
        buf_m = cython.declare(cython.p_char, m)
        sha2(buf_m, len(m), md, self.md_len)
        result = cython.declare(bytes, md[:self.md_len])
        free(md)
        return result

class SHA224(SHA2):
    def __init__(self):
        super(SHA224, self).__init__(SecurityLevel.L0)

class SHA256(SHA2):
    def __init__(self):
        super(SHA256, self).__init__(SecurityLevel.L1)

class SHA384(SHA2):
    def __init__(self):
        super(SHA384, self).__init__(SecurityLevel.L2)

class SHA512(SHA2):
    def __init__(self):
        super(SHA512, self).__init__(SecurityLevel.L3)