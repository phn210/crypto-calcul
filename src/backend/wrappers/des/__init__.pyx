from libc.stdint cimport uint64_t
from wrappers.gmp cimport malloc, free

cdef extern from "des.h":
    cdef const size_t _DES_BLOCK_SIZE "DES_BLOCK_SIZE"

    ctypedef enum des_mode_t:
        DES_ENCRYPT,
        DES_DECRYPT

    void des(uint64_t *, uint64_t *, const uint64_t, int, const char)

cdef extern from "conversion.h":
    unsigned char *pkcs7_padding(unsigned char *, size_t, size_t)
    unsigned char *pkcs7_unpadding(unsigned char *, size_t, size_t)

cdef class DES:

    @staticmethod
    cdef des(bytes data, bytes key, int rounds, int num_blocks, des_mode_t mode):
        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        
        des(in_blocks, out_blocks, rounds, num_blocks, mode)

    def encrypt(self, bytes data, bytes key):
        padded_data = self.pad(data, len(data))

        # Only allow padded input
        assert len(padded_data) / 8 == len(padded_data) // 8
        cdef int num_blocks = len(padded_data) // 8

        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        for i in range(num_blocks):
            in_blocks[i] = <uint64_t>int.from_bytes(padded_data[i*8:i*8+8], byteorder='little')
        cdef uint64_t key_block = <uint64_t>int.from_bytes(key, byteorder='little')

        des(in_blocks, out_blocks, key_block, num_blocks, DES_ENCRYPT)
        result = bytes(<char *>out_blocks)[:len(padded_data)]
        free(in_blocks)
        free(out_blocks)
        return bytes(result)

    def decrypt(self, bytes data, bytes key):
        assert len(data) / 8 == len(data) // 8
        cdef int num_blocks = len(data) // 8

        cdef uint64_t* in_blocks = <uint64_t*>malloc(num_blocks)
        cdef uint64_t* out_blocks = <uint64_t*>malloc(num_blocks)
        for i in range(num_blocks):
            in_blocks[i] = <uint64_t>int.from_bytes(data[i*8:i*8+8], byteorder='little')
        cdef uint64_t key_block = <uint64_t>int.from_bytes(key, byteorder='little')

        des(in_blocks, out_blocks, key_block, num_blocks, DES_DECRYPT)
        result = bytes(<char *>out_blocks)[:len(data)]
        free(in_blocks)
        free(out_blocks)
        result = self.unpad(result, len(result))
        return bytes(result)

    def pad(self, bytes data, size_t length):
        cdef unsigned char *in_bytes = <unsigned char*>data
        cdef unsigned char *out_bytes = pkcs7_padding(<unsigned char*>data, length, _DES_BLOCK_SIZE)
        result = bytes(out_bytes)
        free(out_bytes)
        return result

    def unpad(self, bytes padded_data, size_t length):
        cdef unsigned char *in_bytes = <unsigned char*>padded_data
        cdef unsigned char *out_bytes = pkcs7_unpadding(in_bytes, length, _DES_BLOCK_SIZE)
        result = bytes(out_bytes)
        free(out_bytes)
        return result

