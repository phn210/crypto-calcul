from libc.stdlib cimport malloc
from wrappers.enum import *

cdef extern from "sha_3.h":
    ctypedef struct sha3_ctx:
        pass
    ctypedef sha3_ctx sha3_ctx_t

    void sha3_init(sha3_ctx_t *ctx, size_t md_len);
    void sha3_update(sha3_ctx_t *ctx, const void *m, size_t len);
    void sha3_final(void *md, sha3_ctx_t *ctx);
    char *sha3(const void *m, size_t len, void *md, size_t md_len);
    void shake128_init(sha3_ctx_t *ctx);
    void shake256_init(sha3_ctx_t *ctx);
    void shake_update(sha3_ctx_t *ctx, const void *m, size_t len);
    void shake_xof(sha3_ctx_t *ctx);
    void *shake_out(sha3_ctx_t *ctx, void *out, size_t len);

cdef class SHA3:
    cdef sha3_ctx_t ctx
    cdef int md_len

    def __cinit__(self, int sec_level):
        if sec_level == SecurityLevel._L0.value:
            self.md_len = 28
        elif sec_level == SecurityLevel._L1.value:
            self.md_len = 32
        elif sec_level == SecurityLevel._L2.value:
            self.md_len = 48
        elif sec_level == SecurityLevel._L3.value:
            self.md_len = 64
        else:
            raise ValueError("Invalid Security Level")
        sha3_init(&self.ctx, self.md_len)

    def update(self, bytes m):
        sha3_update(&self.ctx, <char *>m, len(m))

    def digest(self):
        cdef char *md = <char *>malloc(self.md_len)
        sha3_final(md, &self.ctx)
        return bytes(md)
    
    def hash(self, bytes m):
        cdef char *md = <char *>malloc(self.md_len)
        cdef char *out = sha3(<char *>m, len(m), md, self.md_len)
        return bytes(md)[0:self.md_len]

cdef class SHAKE:
    cdef sha3_ctx_t ctx

    def __cinit__(self, int sec_level):
        if sec_level == SecurityLevel._L1.value:
            shake128_init(&self.ctx)
        elif sec_level == SecurityLevel._L3.value:
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