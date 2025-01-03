from libc.stdint cimport uint64_t
from wrappers.gmp cimport malloc, free

cdef extern from "des.h":
    ctypedef struct des_ctx:
        pass

    void des(uint64_t *, uint64_t *, const uint64_t, int, const char)
    void des_padding(char *, char *, size_t)

cdef class DES:

    @staticmethod
    cdef des (bytes data, bytes key, int rounds, char mode):
        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        
        des(&ctx, in_blocks, out_blocks, rounds, mode)

    def encrypt(self, bytes data, bytes key):
        # Only allow padded input
        assert len(data) / 8 == len(data) // 8
        num_blocks = len(data) // 8

        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        for i in range(num_blocks):
            in_blocks[i] = <uint64_t>data[i*8:i*8+8]

        des(in_blocks, out_blocks, key, num_blocks, 'e')
        result = bytes(<char *>out_blocks)
        free(in_blocks)
        free(out_blocks)
        return bytes(result)

    def decrypt(self, bytes data, bytes key):
        # Only allow padded input
        assert len(data) / 8 == len(data) // 8
        num_blocks = len(data) // 8

        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        for i in range(num_blocks):
            in_blocks[i] = <uint64_t>data[i*8:i*8+8]

        des(in_blocks, out_blocks, key, num_blocks, 'd')
        result = bytes(<char *>out_blocks)
        free(in_blocks)
        free(out_blocks)
        return bytes(result)

    def pad(self, bytes data, size_t length):
        cdef char *in_bytes = <char *>data
        cdef char *out_bytes = <char *>malloc(length)
        des_padding(in_bytes, out_bytes, length)
        result = bytes(out_bytes)
        free(in_bytes)
        free(out_bytes)
        return result

