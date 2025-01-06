from libc.stdlib cimport malloc

cdef extern from "sha1.h":
    cdef const size_t _SHA1_DIGEST_SIZE "SHA1_DIGEST_SIZE"

    void *sha1(const void *m, size_t len, void *md, size_t md_len);

cdef class SHA1:    
    def hash(self, bytes m):
        cdef char *md = <char *>malloc(_SHA1_DIGEST_SIZE)
        sha1(<char *>m, len(m), md, _SHA1_DIGEST_SIZE)
        return bytes(md)[0:_SHA1_DIGEST_SIZE]