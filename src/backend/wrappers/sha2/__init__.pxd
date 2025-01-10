from libc.stdlib cimport malloc, free

cdef extern from "sha2.h":
    void *sha2(const void *m, size_t len, void *md, size_t md_len)

cdef class SHA2:
    cdef public size_t md_len

    cpdef bytes hash(self, bytes m)