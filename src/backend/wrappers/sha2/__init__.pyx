from libc.stdlib cimport malloc
from wrappers.enum cimport SecurityLevel

cdef extern from "sha2.h":
    void *sha2(const void *m, size_t len, void *md, size_t md_len)

cdef class SHA2:
    cdef size_t md_len
    
    def __init__(self, SecurityLevel sec_level):
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

    def hash(self, bytes m):
        cdef char *md = <char *>malloc(self.md_len)
        sha2(<char *>m, len(m), md, self.md_len)
        return bytes(md)[0:self.md_len]

cdef class SHA224(SHA2):
    def __init__(self):
        super(SHA224, self).__init__(SecurityLevel.L0)

cdef class SHA256(SHA2):
    def __init__(self):
        super(SHA256, self).__init__(SecurityLevel.L1)

cdef class SHA384(SHA2):
    def __init__(self):
        super(SHA384, self).__init__(SecurityLevel.L2)

cdef class SHA512(SHA2):
    def __init__(self):
        super(SHA512, self).__init__(SecurityLevel.L3)