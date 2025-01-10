from wrappers.enums cimport sec_level_t, hash_func_t
from wrappers.gmp cimport malloc, free

cdef extern from "aes.h":
    const int _AES_BLOCK_SIZE "AES_BLOCK_SIZE"

cdef extern from "hmac.h":
    ctypedef struct hmac_ctx:
        pass
    ctypedef hmac_ctx hmac_ctx_t

    void *hmac(const void *, size_t, const void *, size_t, void *, sec_level_t, hash_func_t)
    int hmac_verify(const void *key, size_t keysize, const void *data, size_t data_len,
                const void *mac, sec_level_t sec_level, hash_func_t hash_function)
    void *hmac_file(const char *filename, const void *key, size_t keysize,
                void *mac, sec_level_t sec_level, hash_func_t hash_function)
    int hmac_file_verify(const char *filename, const void *key, size_t keysize,
                     const void *mac, sec_level_t sec_level, hash_func_t hash_function)

cdef extern from "cbc_mac.h":
    void cbc_mac(const void *, size_t, const void *, size_t, void *, sec_level_t)
    int cbc_mac_verify(const void *key, size_t keysize, const void *data, size_t data_len, const void *mac, sec_level_t sec_level)
    void cbc_mac_file(const char *filename, const void *key, size_t keysize, void *mac, sec_level_t sec_level)
    int cbc_mac_file_verify(const char *filename, const void *key, size_t keysize, const void *mac, sec_level_t sec_level)

cdef class MAC:
    cpdef bytes mac(self, bytes key, bytes data)
    cpdef bytes mac_file(self, str filename, bytes key)
    cpdef verify(self, bytes key, bytes data, bytes mac)
    cpdef verify_file(self, str filename, bytes key, bytes mac)