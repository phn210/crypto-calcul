from libc.stdlib cimport malloc
from wrappers.enum cimport SecurityLevel

cdef extern from "sha_3.h":
    ctypedef struct sha3_ctx:
        size_t md_len
        pass
    ctypedef sha3_ctx sha3_ctx_t

    void sha3_init(sha3_ctx_t *, size_t);
    void sha3_update(sha3_ctx_t *, const void *, size_t);
    void sha3_final(void *, sha3_ctx_t *);
    char *sha3(const void *, size_t, void *, size_t);
    void shake128_init(sha3_ctx_t *);
    void shake256_init(sha3_ctx_t *);
    void shake_update(sha3_ctx_t *, const void *, size_t);
    void shake_xof(sha3_ctx_t *);
    void *shake_out(sha3_ctx_t *, void *, size_t);

cdef class SHA3:
    cdef sha3_ctx_t ctx

    def __cinit__(self, SecurityLevel sec_level):
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
        sha3_init(&self.ctx, md_len)

    def update(self, bytes m):
        sha3_update(&self.ctx, <char *>m, len(m))

    def digest(self):
        cdef char *md = <char *>malloc(self.ctx.md_len)
        sha3_final(md, &self.ctx)
        return bytes(md)
    
    def hash(self, bytes m):
        cdef char *md = <char *>malloc(self.ctx.md_len)
        cdef char *out = sha3(<char *>m, len(m), md, self.ctx.md_len)
        return bytes(md)[0:self.ctx.md_len]

cdef class SHAKE:
    cdef sha3_ctx_t ctx

    def __cinit__(self, int sec_level):
        if sec_level == SecurityLevel.L1:
            shake128_init(&self.ctx)
        elif sec_level == SecurityLevel.L3:
            shake256_init(&self.ctx)
        else:
            raise ValueError("Invalid Security Level")
    
    def update(self, bytes m):
        shake_update(&self.ctx, <char *>m, len(m))
    
    def xof(self):
        shake_xof(&self.ctx)
    
    def squeeze(self, int len):
        cdef char *out = <char *>malloc(len)
        shake_out(&self.ctx, <char *>out, len)
        return bytes(out)[0:len]