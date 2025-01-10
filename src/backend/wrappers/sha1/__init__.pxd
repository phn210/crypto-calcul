from libc.stdlib cimport malloc, free

cdef extern from "sha1.h":
    cdef const size_t _SHA1_DIGEST_SIZE "SHA1_DIGEST_SIZE"

    void *sha1(const void *m, size_t len, void *md, size_t md_len);

cdef class SHA1:    
    cpdef hash(self, bytes m)