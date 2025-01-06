from libc.stdlib cimport malloc

cdef extern from "md5.h":
    cdef const size_t _MD5_DIGEST_SIZE "MD5_DIGEST_SIZE"

    void *md5(const void *m, size_t len, void *md, size_t md_len);

cdef class MD5:    
    def hash(self, bytes m):
        cdef char *md = <char *>malloc(_MD5_DIGEST_SIZE)
        md5(<char *>m, len(m), md, _MD5_DIGEST_SIZE)
        return bytes(md)[0:_MD5_DIGEST_SIZE]