from libc.stdlib cimport malloc, free
from libc.stdint cimport uint64_t
from wrappers.enums cimport cc_status_t, check

cdef extern from "des.h":
    ctypedef enum des_mode_t:
        DES_ENCRYPT,
        DES_DECRYPT

    cdef const size_t _DES_BLOCK_SIZE "DES_BLOCK_SIZE"

    void des(uint64_t *, uint64_t *, const uint64_t, int, des_mode_t)
    cc_status_t des_file(const char *, const char *, const uint64_t, des_mode_t)

cdef extern from "conversion.h":
    cc_status_t pkcs7_padding(const unsigned char *, size_t, unsigned char **, size_t *, size_t)
    cc_status_t pkcs7_unpadding(const unsigned char *, size_t, unsigned char **, size_t *, size_t)

cdef class DES:
    cpdef des(self, bytes data, bytes key, mode)
    cpdef des_file(self, str file_path, str output_path, bytes key, mode)
    cpdef bytes encrypt(self, bytes data, bytes key)
    cpdef bytes decrypt(self, bytes data, bytes key)
    cpdef void encrypt_file(self, str file_path, str output_path, bytes key)
    cpdef void decrypt_file(self, str file_path, str output_path, bytes key)
    cpdef bytes pad(self, bytes data, size_t length)
    cpdef bytes unpad(self, bytes padded_data, size_t length)
