import cython
from wrappers.enums import SecurityLevel, HashFunction

@cython.cclass
class MAC:
    @cython.ccall
    def mac(self, key: bytes, data: bytes) -> bytes:
        pass
    
    @cython.ccall
    def mac_file(self, file_path: str, key: bytes) -> bytes:
        pass
    
    @cython.ccall
    def verify(self, key: bytes, data: bytes, mac: bytes):
        pass
    
    @cython.ccall
    def verify_file(self, file_path: str, key: bytes, mac: bytes):
        pass

@cython.cclass
class HMAC(MAC):
    mac_len: int
    sec_level: SecurityLevel
    hash_function: HashFunction

    def __init__(self, sec_level: SecurityLevel, hash_function: HashFunction):
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

    @cython.ccall
    def mac(self, key: bytes, data: bytes) -> bytes:
        mac = cython.cast(cython.p_char, malloc(self.mac_len))
        hmac(cython.cast(cython.p_void, key), len(key), cython.cast(cython.p_void, data), len(data),
            cython.cast(cython.p_void, mac), self.sec_level.value, self.hash_function.value)
        result = cython.declare(bytes, mac[:self.mac_len])
        free(mac)
        return result
    
    @cython.ccall
    def mac_file(self, file_path: str, key: bytes) -> bytes:
        in_file = file_path.encode('utf-8')
        mac = cython.cast(cython.p_char, malloc(self.mac_len))
        hmac_file(cython.cast(cython.p_char, in_file), cython.cast(cython.p_void, key), len(key),
            cython.cast(cython.p_void, mac), self.sec_level.value, self.hash_function.value)
        result = cython.declare(bytes, mac[:self.mac_len])
        free(mac)
        return result
    
    @cython.ccall
    def verify(self, key: bytes, data: bytes, mac: bytes):
        return bool(hmac_verify(cython.cast(cython.p_void, key), len(key), cython.cast(cython.p_void, data), len(data),
            cython.cast(cython.p_void, mac), self.sec_level.value, self.hash_function.value))
        
    @cython.ccall
    def verify_file(self, file_path: str, key: bytes, mac: bytes):
        in_file = file_path.encode('utf-8')
        return bool(hmac_file_verify(cython.cast(cython.p_char, in_file), cython.cast(cython.p_void, key), len(key),
            cython.cast(cython.p_void, mac), self.sec_level.value, self.hash_function.value))

@cython.cclass
class CBCMAC(MAC):
    sec_level: SecurityLevel

    def __init__(self, sec_level: SecurityLevel):
        self.sec_level = sec_level

    @cython.ccall
    def mac(self, key: bytes, data: bytes) -> bytes:
        mac = cython.cast(cython.p_char, malloc(_AES_BLOCK_SIZE))
        cbc_mac(cython.cast(cython.p_void, key), len(key), cython.cast(cython.p_void, data), len(data),
            cython.cast(cython.p_void, mac), self.sec_level.value)
        result = cython.declare(bytes, mac[:_AES_BLOCK_SIZE])
        free(mac)
        return result
    
    @cython.ccall
    def mac_file(self, file_path: str, key: bytes) -> bytes:
        in_file = file_path.encode('utf-8')
        mac = cython.cast(cython.p_char, malloc(_AES_BLOCK_SIZE))
        cbc_mac_file(cython.cast(cython.p_char, in_file), cython.cast(cython.p_void, key), len(key),
            cython.cast(cython.p_void, mac), self.sec_level.value)
        result = cython.declare(bytes, mac[:_AES_BLOCK_SIZE])
        free(mac)
        return result
    
    @cython.ccall
    def verify(self, key: bytes, data: bytes, mac: bytes):
        return bool(cbc_mac_verify(cython.cast(cython.p_void, key), len(key), cython.cast(cython.p_void, data), len(data),
            cython.cast(cython.p_void, mac), self.sec_level.value))
        
    @cython.ccall
    def verify_file(self, file_path: str, key: bytes, mac: bytes):
        in_file = file_path.encode('utf-8')
        return bool(cbc_mac_file_verify(cython.cast(cython.p_char, in_file), cython.cast(cython.p_void, key), len(key),
            cython.cast(cython.p_void, mac), self.sec_level.value))