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
        mac_len: cython.size_t = 0
        check(hmac_length(sec_level.value, hash_function.value, cython.address(mac_len)))
        self.mac_len = mac_len

    @cython.ccall
    def mac(self, key: bytes, data: bytes) -> bytes:
        mac = cython.cast(cython.p_char, malloc(self.mac_len))
        status = hmac(cython.cast(cython.p_uchar, key), len(key), cython.cast(cython.p_uchar, data), len(data),
            cython.cast(cython.p_uchar, mac), self.sec_level.value, self.hash_function.value)
        result = cython.declare(bytes, mac[:self.mac_len])
        free(mac)
        check(status)
        return result

    @cython.ccall
    def mac_file(self, file_path: str, key: bytes) -> bytes:
        in_file = file_path.encode('utf-8')
        mac = cython.cast(cython.p_char, malloc(self.mac_len))
        status = hmac_file(cython.cast(cython.p_char, in_file), cython.cast(cython.p_uchar, key), len(key),
            cython.cast(cython.p_uchar, mac), self.sec_level.value, self.hash_function.value)
        result = cython.declare(bytes, mac[:self.mac_len])
        free(mac)
        check(status)
        return result

    @cython.ccall
    def verify(self, key: bytes, data: bytes, mac: bytes):
        return bool(check_verify(hmac_verify(cython.cast(cython.p_uchar, key), len(key), cython.cast(cython.p_uchar, data), len(data),
            cython.cast(cython.p_uchar, mac), len(mac), self.sec_level.value, self.hash_function.value)))

    @cython.ccall
    def verify_file(self, file_path: str, key: bytes, mac: bytes):
        in_file = file_path.encode('utf-8')
        return bool(check_verify(hmac_file_verify(cython.cast(cython.p_char, in_file), cython.cast(cython.p_uchar, key), len(key),
            cython.cast(cython.p_uchar, mac), len(mac), self.sec_level.value, self.hash_function.value)))

@cython.cclass
class CBCMAC(MAC):
    sec_level: SecurityLevel

    def __init__(self, sec_level: SecurityLevel):
        self.sec_level = sec_level

    @cython.ccall
    def mac(self, key: bytes, data: bytes) -> bytes:
        mac = cython.cast(cython.p_char, malloc(_AES_BLOCK_SIZE))
        status = cbc_mac(cython.cast(cython.p_uchar, key), len(key), cython.cast(cython.p_uchar, data), len(data),
            cython.cast(cython.p_uchar, mac), self.sec_level.value)
        result = cython.declare(bytes, mac[:_AES_BLOCK_SIZE])
        free(mac)
        check(status)
        return result

    @cython.ccall
    def mac_file(self, file_path: str, key: bytes) -> bytes:
        in_file = file_path.encode('utf-8')
        mac = cython.cast(cython.p_char, malloc(_AES_BLOCK_SIZE))
        status = cbc_mac_file(cython.cast(cython.p_char, in_file), cython.cast(cython.p_uchar, key), len(key),
            cython.cast(cython.p_uchar, mac), self.sec_level.value)
        result = cython.declare(bytes, mac[:_AES_BLOCK_SIZE])
        free(mac)
        check(status)
        return result

    @cython.ccall
    def verify(self, key: bytes, data: bytes, mac: bytes):
        return bool(check_verify(cbc_mac_verify(cython.cast(cython.p_uchar, key), len(key), cython.cast(cython.p_uchar, data), len(data),
            cython.cast(cython.p_uchar, mac), len(mac), self.sec_level.value)))

    @cython.ccall
    def verify_file(self, file_path: str, key: bytes, mac: bytes):
        in_file = file_path.encode('utf-8')
        return bool(check_verify(cbc_mac_file_verify(cython.cast(cython.p_char, in_file), cython.cast(cython.p_uchar, key), len(key),
            cython.cast(cython.p_uchar, mac), len(mac), self.sec_level.value)))
