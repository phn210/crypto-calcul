from wrappers.enums cimport sec_level_t, hash_func_t
from wrappers.gmp cimport malloc, free

cdef extern from "aes.h":
    const int _AES_BLOCK_SIZE "AES_BLOCK_SIZE"

cdef extern from "hmac.h":
    ctypedef struct hmac_ctx:
        pass
    ctypedef hmac_ctx hmac_ctx_t

    void *hmac(const void *, size_t, const void *, size_t, void *, sec_level_t, hash_func_t)

cdef extern from "cbc_mac.h":
    void cbc_mac(const void *, size_t, const void *, size_t, void *, sec_level_t)

cdef class MAC:
    cpdef bytes mac(self, bytes key, bytes data)