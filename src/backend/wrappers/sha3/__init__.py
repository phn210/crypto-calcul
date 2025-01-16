import cython
from wrappers.enums import SecurityLevel

@cython.cclass
class SHA3:
    def __init__(self, sec_level: SecurityLevel):
        md_len = 0
        if sec_level == SecurityLevel.L0:
            md_len = 28
        elif sec_level == SecurityLevel.L1:
            md_len = 32
        elif sec_level == SecurityLevel.L2:
            md_len = 48
        elif sec_level == SecurityLevel.L3:
            md_len = 64
        else:
            raise ValueError("Invalid Security Level")
        sha3_init(cython.address(self.ctx), md_len)

    @cython.ccall
    def update(self, m: bytes) -> cython.void:
        buf_m = cython.declare(cython.p_char, m)
        sha3_update(cython.address(self.ctx), buf_m, len(m))

    @cython.ccall
    def digest(self) -> bytes:
        md = cython.cast(cython.p_char, malloc(self.ctx.md_len))
        sha3_final(md, cython.address(self.ctx))
        result = cython.declare(bytes, md)
        free(md)
        return result
    
    @cython.ccall
    def hash(self, m: bytes) -> bytes:
        md = cython.cast(cython.p_char, malloc(self.ctx.md_len))
        buf_m = cython.declare(cython.p_char, m)
        sha3(buf_m, len(m), md, self.ctx.md_len)
        result = cython.declare(bytes, md[:self.ctx.md_len])
        free(md)
        return result

@cython.cclass
class SHAKE:
    def __init__(self, sec_level: SecurityLevel):
        if sec_level == SecurityLevel.L1:
            shake128_init(cython.address(self.ctx))
        elif sec_level == SecurityLevel.L3:
            shake256_init(cython.address(self.ctx))
        else:
            raise ValueError("Invalid Security Level")
    
    @cython.ccall
    def update(self, m: bytes) -> cython.void:
        buf_m = cython.declare(cython.p_char, m)
        shake_update(cython.address(self.ctx), buf_m, len(m))
    
    @cython.ccall
    def xof(self) -> cython.void:
        shake_xof(cython.address(self.ctx))
    
    @cython.ccall
    def squeeze(self, len: cython.int) -> bytes:
        out = cython.cast(cython.p_char, malloc(len))
        shake_out(cython.address(self.ctx), out, len)
        result = cython.declare(bytes, out[:len])
        free(out)
        return result

class SHA3_224(SHA3):
    def __init__(self):
        super(SHA3_224, self).__init__(SecurityLevel.L0)

class SHA3_256(SHA3):
    def __init__(self):
        super(SHA3_256, self).__init__(SecurityLevel.L1)

class SHA3_384(SHA3):
    def __init__(self):
        super(SHA3_384, self).__init__(SecurityLevel.L2)

class SHA3_512(SHA3):
    def __init__(self):
        super(SHA3_512, self).__init__(SecurityLevel.L3)

class SHAKE128(SHAKE):
    def __init__(self):
        super(SHAKE128, self).__init__(SecurityLevel.L1)

class SHAKE256(SHAKE):
    def __init__(self):
        super(SHAKE256, self).__init__(SecurityLevel.L3)