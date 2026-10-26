"""AES, DES and MACs. Key material is truncated or zero-padded to the size the algorithm needs."""
import hmac as _hmac
from enum import Enum

from ._core import call_out, check, check_verify, data, fit, lib
from .primitives import HashFunction, SecurityLevel

_AES_BLOCK_SIZE = 16
_DES_KEY_SIZE = 8
_AES_KEY_SIZES = {SecurityLevel.L1: 16, SecurityLevel.L2: 24, SecurityLevel.L3: 32}


class AESMode(Enum):
    ECB = lib.CC_AES_ECB
    CBC = lib.CC_AES_CBC
    CFB = lib.CC_AES_CFB
    OFB = lib.CC_AES_OFB
    CTR = lib.CC_AES_CTR


class AES:
    """AES with PKCS#7 padding; the security level (L1 to L3) selects a 128, 192 or 256-bit key."""

    def __init__(self, sec_level: SecurityLevel, mode: AESMode):
        if sec_level not in _AES_KEY_SIZES:
            raise ValueError("AES supports security levels L1, L2 and L3")
        self.key_size = _AES_KEY_SIZES[sec_level]
        self.mode = mode

    def _params(self, key: bytes, iv: bytes):
        return self.mode.value, data(fit(key, self.key_size)), self.key_size, data(fit(iv, _AES_BLOCK_SIZE))

    def _iv(self, iv: bytes, nonce: bytes) -> bytes:
        # CTR mode uses the nonce as its initial counter block
        return nonce if self.mode == AESMode.CTR else iv

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes = b"", nonce: bytes = b"") -> bytes:
        return call_out(lib.cc_aes_encrypt, *self._params(key, self._iv(iv, nonce)), data(plaintext), len(plaintext),
                        capacity=len(plaintext) + _AES_BLOCK_SIZE)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes = b"", nonce: bytes = b"") -> bytes:
        return call_out(lib.cc_aes_decrypt, *self._params(key, self._iv(iv, nonce)), data(ciphertext), len(ciphertext),
                        capacity=len(ciphertext))

    def encrypt_file(self, input_path: str, output_path: str, key: bytes, iv: bytes = b"") -> None:
        check(lib.cc_aes_encrypt_file(*self._params(key, iv), input_path.encode(), output_path.encode()))

    def decrypt_file(self, input_path: str, output_path: str, key: bytes, iv: bytes = b"") -> None:
        check(lib.cc_aes_decrypt_file(*self._params(key, iv), input_path.encode(), output_path.encode()))


class DES:
    """DES-ECB with PKCS#7 padding and an 8-byte key."""

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        return call_out(lib.cc_des_encrypt, data(fit(key, _DES_KEY_SIZE)), data(plaintext), len(plaintext),
                        capacity=len(plaintext) + _DES_KEY_SIZE)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return call_out(lib.cc_des_decrypt, data(fit(key, _DES_KEY_SIZE)), data(ciphertext), len(ciphertext),
                        capacity=len(ciphertext))

    def encrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        check(lib.cc_des_encrypt_file(data(fit(key, _DES_KEY_SIZE)), input_path.encode(), output_path.encode()))

    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> None:
        check(lib.cc_des_decrypt_file(data(fit(key, _DES_KEY_SIZE)), input_path.encode(), output_path.encode()))


class HMAC:
    """HMAC; for SHA-2 and SHA-3 the security level selects the hash size."""

    def __init__(self, sec_level: SecurityLevel, hash_function: HashFunction):
        self.sec_level = sec_level
        self.hash_function = hash_function

    def mac(self, key: bytes, message: bytes) -> bytes:
        return call_out(lib.cc_hmac, self.hash_function.value, self.sec_level.value,
                        data(key), len(key), data(message), len(message))

    def mac_file(self, file_path: str, key: bytes) -> bytes:
        return call_out(lib.cc_hmac_file, self.hash_function.value, self.sec_level.value,
                        data(key), len(key), file_path.encode())

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        return check_verify(lib.cc_hmac_verify(self.hash_function.value, self.sec_level.value,
                                               data(key), len(key), data(message), len(message), data(tag), len(tag)))

    def verify_file(self, file_path: str, key: bytes, tag: bytes) -> bool:
        return _hmac.compare_digest(self.mac_file(file_path, key), tag)


class CBCMAC:
    """AES-CBC-MAC with a 16-byte tag; levels L1 to L3 select the AES key size."""

    def __init__(self, sec_level: SecurityLevel):
        self.sec_level = sec_level

    def mac(self, key: bytes, message: bytes) -> bytes:
        return call_out(lib.cc_cbc_mac, self.sec_level.value, data(key), len(key), data(message), len(message))

    def mac_file(self, file_path: str, key: bytes) -> bytes:
        return call_out(lib.cc_cbc_mac_file, self.sec_level.value, data(key), len(key), file_path.encode())

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        return check_verify(lib.cc_cbc_mac_verify(self.sec_level.value, data(key), len(key),
                                                  data(message), len(message), data(tag), len(tag)))

    def verify_file(self, file_path: str, key: bytes, tag: bytes) -> bool:
        return _hmac.compare_digest(self.mac_file(file_path, key), tag)
