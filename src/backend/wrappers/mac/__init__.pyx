from wrappers.gmp cimport malloc, free
from wrappers.enum cimport SecurityLevel, HashFunction

cdef extern from "hmac.h":
    ctypedef struct hmac_ctx:
        pass
    ctypedef hmac_ctx hmac_ctx_t

    void *hmac(const void *, size_t, const void *, size_t, void *, unsigned char, unsigned char)

cdef class HMAC:
    cdef public int sec_level, hash_function, mac_len

    def __cinit__(self, SecurityLevel sec_level, HashFunction hash_function):
        self.sec_level = sec_level
        self.hash_function = hash_function
        if hash_function == HashFunction.MD5:
            self.mac_len = 16
        elif hash_function == HashFunction.SHA1:
            self.mac_len = 20
        else:
            if sec_level == SecurityLevel.L0:
                self.mac_len = 28
            elif sec_level == SecurityLevel.L1:
                self.mac_len = 32
            elif sec_level == SecurityLevel.L2:
                self.mac_len = 48
            else:
                self.mac_len = 64

    def mac(self, bytes key, bytes data):
        cdef char *key_bytes = <char *>key
        cdef char *data_bytes = <char *>data
        cdef char *mac = <char *>malloc(self.mac_len)
        hmac(<void *>key_bytes, len(key), <void *>data_bytes, len(data),
            <void *>mac, self.sec_level, self.hash_function)
        result = bytes(mac[:self.mac_len])
        free(mac)
        return result