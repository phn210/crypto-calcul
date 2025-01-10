from libc.stdlib cimport malloc, free

cdef extern from "sha3.h":
    ctypedef struct sha3_ctx:
        size_t md_len
        pass
    ctypedef sha3_ctx sha3_ctx_t

    void sha3_init(sha3_ctx_t *, size_t);
    void sha3_update(sha3_ctx_t *, const void *, size_t);
    void sha3_final(void *, sha3_ctx_t *);
    void *sha3(const void *, size_t, void *, size_t);
    void shake128_init(sha3_ctx_t *);
    void shake256_init(sha3_ctx_t *);
    void shake_update(sha3_ctx_t *, const void *, size_t);
    void shake_xof(sha3_ctx_t *);
    void *shake_out(sha3_ctx_t *, void *, size_t);

cdef class SHA3:
    cdef sha3_ctx_t ctx

    cpdef void update(self, bytes m)
    cpdef bytes digest(self)
    cpdef bytes hash(self, bytes m)

cdef class SHAKE:
    cdef sha3_ctx_t ctx
    
    cpdef void update(self, bytes m)
    cpdef void xof(self) 
    cpdef bytes squeeze(self, int len)