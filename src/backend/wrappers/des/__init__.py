import cython

@cython.cclass
class DES:
    @cython.ccall
    def des(self, data: bytes, key: bytes, mode):
        if len(data) % _DES_BLOCK_SIZE != 0:
            raise ValueError("DES input length must be a multiple of 8 bytes")
        num_blocks = len(data) // _DES_BLOCK_SIZE

        in_blocks = cython.cast(cython.p_ulonglong, malloc(num_blocks * _DES_BLOCK_SIZE))
        out_blocks = cython.cast(cython.p_ulonglong, malloc(num_blocks * _DES_BLOCK_SIZE))

        for i in range(num_blocks):
            in_blocks[i] = cython.cast(cython.ulonglong, int.from_bytes(data[i*8:i*8+8], byteorder='little'))
        key_block = cython.cast(cython.ulonglong, int.from_bytes(key, byteorder='little'))

        des(in_blocks, out_blocks, key_block, num_blocks, mode)
        result = cython.declare(bytes, cython.cast(cython.p_char, out_blocks)[:len(data)])
        free(in_blocks)
        free(out_blocks)
        return result

    @cython.ccall
    def des_file(self, in_path: str, out_path: str, key: bytes, mode):
        infile = in_path.encode('utf-8')
        outfile = out_path.encode('utf-8')

        in_ptr = cython.cast(cython.p_char, infile)
        out_ptr = cython.cast(cython.p_char, outfile)
        key_block = cython.cast(cython.ulonglong, int.from_bytes(key, byteorder='little'))

        check(des_file(in_ptr, out_ptr, key_block, mode))

    @cython.ccall
    def encrypt_file(self, file_path: str, output_path: str, key: bytes) -> cython.void:
        self.des_file(file_path, output_path, key, DES_ENCRYPT)

    @cython.ccall
    def decrypt_file(self, file_path: str, output_path: str, key: bytes) -> cython.void:
        self.des_file(file_path, output_path, key, DES_DECRYPT)

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
        padded_data: cython.p_uchar = cython.NULL
        padded_len: cython.size_t = 0
        check(pkcs7_padding(cython.cast(cython.p_uchar, data), length, cython.address(padded_data), cython.address(padded_len), _DES_BLOCK_SIZE))
        result = cython.declare(bytes, padded_data[:padded_len])
        free(padded_data)
        return result

    @cython.ccall
    def unpad(self, padded_data: bytes, length: cython.size_t) -> bytes:
        data: cython.p_uchar = cython.NULL
        unpadded_len: cython.size_t = 0
        check(pkcs7_unpadding(cython.cast(cython.p_uchar, padded_data), length, cython.address(data), cython.address(unpadded_len), _DES_BLOCK_SIZE))
        result = cython.declare(bytes, data[:unpadded_len])
        free(data)
        return result
