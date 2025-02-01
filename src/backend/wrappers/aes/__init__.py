import cython
from enum import Enum
from wrappers.enums import SecurityLevel

class AESMode(Enum):
    ECB = AES_MODE_ECB
    CBC = AES_MODE_CBC
    CFB = AES_MODE_CFB
    OFB = AES_MODE_OFB
    CTR = AES_MODE_CTR
    GCM = AES_MODE_GCM

@cython.cclass
class AES:
    def __init__(self, sec_level: SecurityLevel, mode: AESMode):
        if sec_level == SecurityLevel.L1:
            self.key_size = AES_KEY_SIZE_128
        elif sec_level == SecurityLevel.L2:
            self.key_size = AES_KEY_SIZE_192
        elif sec_level == SecurityLevel.L3:
            self.key_size = AES_KEY_SIZE_256
        else:
            raise ValueError("Invalid security level")
        
        if mode == AESMode.ECB:
            self.mode = AES_MODE_ECB
        elif mode == AESMode.CBC:
            self.mode = AES_MODE_CBC
        elif mode == AESMode.CFB:
            self.mode = AES_MODE_CFB
        elif mode == AESMode.OFB:
            self.mode = AES_MODE_OFB
        elif mode == AESMode.CTR:
            self.mode = AES_MODE_CTR
        else:
            raise ValueError("Invalid AES mode")

    @cython.ccall
    def aes(self, data: bytes, key: bytes, iv: bytes, nonce: bytes, f: cython.char) -> bytes:
        data_len = cython.cast(cython.size_t, len(data))
        assert data_len / _AES_BLOCK_SIZE == data_len // _AES_BLOCK_SIZE

        in_ptr = cython.cast(cython.p_uchar, data)
        out_ptr = cython.cast(cython.p_uchar, malloc(data_len))

        key = key[:self.key_size].ljust(self.key_size, b'\0')
        iv = iv[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, b'\0')
        nonce = nonce[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, b'\0')
        
        key_ptr = cython.cast(cython.p_uchar, key)
        iv_ptr = cython.cast(cython.p_uchar, iv)
        nonce_ptr = cython.cast(cython.p_uchar, nonce)

        if f == 0:
            if self.mode == AES_MODE_ECB:
                aes_encrypt_ecb(in_ptr, out_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CBC:
                aes_encrypt_cbc(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CFB:
                aes_encrypt_cfb(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_OFB:
                aes_encrypt_ofb(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CTR:
                aes_ctr(in_ptr, out_ptr, nonce_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_GCM:
                raise NotImplementedError("AES GCM mode is not implemented")
        elif f == 1:
            if self.mode == AES_MODE_ECB:
                aes_decrypt_ecb(in_ptr, out_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CBC:
                aes_decrypt_cbc(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CFB:
                aes_decrypt_cfb(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_OFB:
                aes_decrypt_ofb(in_ptr, out_ptr, iv_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_CTR:
                aes_ctr(in_ptr, out_ptr, nonce_ptr, key_ptr, data_len, self.key_size)
            elif self.mode == AES_MODE_GCM:
                raise NotImplementedError("AES GCM mode is not implemented")

        result = cython.declare(bytes, out_ptr[:data_len])
        free(out_ptr)
        return result
    
    @cython.ccall
    def encrypt(self, data: bytes, key: bytes, iv: bytes, nonce: bytes) -> bytes:
        padded_data = self.pad(data, len(data))
        return self.aes(padded_data, key, iv, nonce, 0)

    @cython.ccall
    def decrypt(self, data: bytes, key: bytes, iv: bytes, nonce: bytes) -> bytes:
        decrypted = self.aes(data, key, iv, nonce, 1)
        result = self.unpad(decrypted, len(decrypted))
        return result
    
    @cython.ccall
    def encrypt_file(self, file_path: str, output_path: str, key: bytes, iv: bytes) -> cython.void:
        infile = file_path.encode('utf-8')
        outfile = output_path.encode('utf-8')
        in_ptr = cython.cast(cython.p_char, infile)
        out_ptr = cython.cast(cython.p_char, outfile)

        key = key[:self.key_size].ljust(self.key_size, b'\0')
        iv = iv[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, b'\0')
        
        key_ptr = cython.cast(cython.p_uchar, key)
        iv_ptr = cython.cast(cython.p_uchar, iv)

        aes_file_encrypt(in_ptr, out_ptr, key_ptr, iv_ptr, self.key_size, self.mode)

    @cython.ccall
    def decrypt_file(self, file_path: str, output_path: str, key: bytes, iv: bytes) -> cython.void:
        infile = file_path.encode('utf-8')
        outfile = output_path.encode('utf-8')
        in_ptr = cython.cast(cython.p_char, infile)
        out_ptr = cython.cast(cython.p_char, outfile)

        key = key[:self.key_size].ljust(self.key_size, b'\0')
        iv = iv[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, b'\0')
        
        key_ptr = cython.cast(cython.p_uchar, key)
        iv_ptr = cython.cast(cython.p_uchar, iv)

        aes_file_decrypt(in_ptr, out_ptr, key_ptr, iv_ptr, self.key_size, self.mode)

    @cython.ccall
    def pad(self, data: bytes, length: cython.size_t) -> bytes:
        in_bytes = cython.declare(cython.p_uchar, data)
        padded_len: cython.size_t = 0
        padded_data = pkcs7_padding(in_bytes, length, cython.address(padded_len), _AES_BLOCK_SIZE)
        result = cython.declare(bytes, padded_data[:padded_len])
        return result[:padded_len]

    @cython.ccall
    def unpad(self, padded_data: bytes, length: cython.size_t) -> bytes:
        in_bytes = cython.declare(cython.p_uchar, padded_data)
        unpadded_len: cython.size_t = 0
        data = pkcs7_unpadding(in_bytes, length, cython.address(unpadded_len), _AES_BLOCK_SIZE)
        result = cython.declare(bytes, data[:unpadded_len])
        return result[:unpadded_len]
    
class AES_128(AES):
    def __init__(self, mode: AESMode):
        super().__init__(SecurityLevel.L1, mode)

class AES_192(AES):
    def __init__(self, mode: AESMode):
        super().__init__(SecurityLevel.L2, mode)

class AES_256(AES):
    def __init__(self, mode: AESMode):
        super().__init__(SecurityLevel.L3, mode)

class AES_128_ECB(AES_128):
    def __init__(self):
        super().__init__(AESMode.ECB)

class AES_128_CBC(AES_128):
    def __init__(self):
        super().__init__(AESMode.CBC)

class AES_128_CFB(AES_128):
    def __init__(self):
        super().__init__(AESMode.CFB)

class AES_128_OFB(AES_128):
    def __init__(self):
        super().__init__(AESMode.OFB)

class AES_128_CTR(AES_128):
    def __init__(self):
        super().__init__(AESMode.CTR)

class AES_192_ECB(AES_192):
    def __init__(self):
        super().__init__(AESMode.ECB)

class AES_192_CBC(AES_192):
    def __init__(self):
        super().__init__(AESMode.CBC)

class AES_192_CFB(AES_192):
    def __init__(self):
        super().__init__(AESMode.CFB)

class AES_192_OFB(AES_192):
    def __init__(self):
        super().__init__(AESMode.OFB)

class AES_192_CTR(AES_192):
    def __init__(self):
        super().__init__(AESMode.CTR)

class AES_256_ECB(AES_256):
    def __init__(self):
        super().__init__(AESMode.ECB)

class AES_256_CBC(AES_256):
    def __init__(self):
        super().__init__(AESMode.CBC)

class AES_256_CFB(AES_256):
    def __init__(self):
        super().__init__(AESMode.CFB)

class AES_256_OFB(AES_256):
    def __init__(self):
        super().__init__(AESMode.OFB)

class AES_256_CTR(AES_256):
    def __init__(self):
        super().__init__(AESMode.CTR)