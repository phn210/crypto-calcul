import cython

@cython.cclass
class DES:
    @cython.ccall
    def des(self, data: bytes, key: bytes, mode):
        assert len(data) / 8 == len(data) // 8
        num_blocks = len(data) // 8

        in_blocks = cython.cast(cython.p_ulonglong, malloc(num_blocks))
        out_blocks = cython.cast(cython.p_ulonglong, malloc(num_blocks))

        for i in range(num_blocks):
            in_blocks[i] = cython.cast(cython.ulonglong, int.from_bytes(data[i*8:i*8+8], byteorder='little'))
        key_block = cython.cast(cython.ulonglong, int.from_bytes(key, byteorder='little'))

        des(in_blocks, out_blocks, key_block, num_blocks, mode)
        result = cython.cast(bytes, cython.cast(cython.p_char, out_blocks))[:len(data)]
        free(in_blocks)
        free(out_blocks)
        return result

    @cython.ccall
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        padded_data = self.pad(data, len(data))
        return self.des(padded_data, key, DES_ENCRYPT)

    @cython.ccall
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        decrypted = self.des(data, key, DES_DECRYPT)
        result = self.unpad(decrypted, len(decrypted))
        return result

    @cython.ccall
    def pad(self, data: bytes, length: cython.size_t) -> bytes:
        in_bytes = cython.cast(cython.p_uchar, data)
        result = cython.cast(bytes, pkcs7_padding(in_bytes, length, _DES_BLOCK_SIZE))
        return result

    @cython.ccall
    def unpad(self, padded_data: bytes, length: cython.size_t) -> bytes:
        in_bytes = cython.cast(cython.p_uchar, padded_data)
        result = cython.cast(bytes, pkcs7_unpadding(in_bytes, length, _DES_BLOCK_SIZE))
        return result