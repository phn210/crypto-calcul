from libc.stdlib cimport malloc, free

cdef extern from "md5.h":
    cdef const size_t _MD5_DIGEST_SIZE "MD5_DIGEST_SIZE"

    void *md5(const void *m, size_t len, void *md, size_t md_len);

cdef class MD5:    
    cpdef hash(self, bytes m)