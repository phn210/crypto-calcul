import cython
from enum import Enum
from wrappers.enums import SecurityLevel
from wrappers.gmp import GMPInteger
from wrappers.enums import CryptoError

class RSAAlgo(Enum):
    STANDARD = RSA_STANDARD
    CRT = RSA_CRT

class RSAVariant(Enum):
    TEXTBOOK = 0
    PKCS1 = 1
    SECURE = 2

class RSAPublicParams:
    def __init__(self, n_bits: int, e: GMPInteger):
        self.n_bits = n_bits
        self.e = e

class RSAPublicKey:
    def __init__(self, n: GMPInteger, e: GMPInteger):
        self.n = n
        self.e = e

class RSAPrivateKey:
    def __init__(self, n: GMPInteger, p: GMPInteger, q: GMPInteger, d: GMPInteger, dp: GMPInteger, dq: GMPInteger, q_inv: GMPInteger):
        self.n = n
        self.p = p
        self.q = q
        self.d = d
        self.dp = dp
        self.dq = dq
        self.q_inv = q_inv

@cython.cclass
class RSA:
    def __init__(self, sec_level: SecurityLevel, variant: RSAVariant):
        check(rsa_setup(cython.address(self.pp), sec_level.value))
        self.has_params = True
        self.sec_level = sec_level.value
        self.variant = variant.value

    def __dealloc__(self):
        if self.has_key:
            rsa_free_keys(cython.address(self.sk), cython.address(self.pk))
        if self.has_params:
            rsa_free_params(cython.address(self.pp))

    @property
    def params(self) -> RSAPublicParams:
        e = GMPInteger()
        mpz_set(e.value, self.pp.e)
        return RSAPublicParams(self.pp.n_bits, e)
    
    @property
    def pubKey(self) -> RSAPublicKey:
        n = GMPInteger()
        e = GMPInteger()
        mpz_set(n.value, self.pk.n)
        mpz_set(e.value, self.pk.e)
        return RSAPublicKey(n, e)
    
    @property
    def prvKey(self) -> RSAPrivateKey:
        n = GMPInteger()
        p = GMPInteger()
        q = GMPInteger()
        d = GMPInteger()
        dp = GMPInteger()
        dq = GMPInteger()
        q_inv = GMPInteger()
        mpz_set(n.value, self.sk.n)
        mpz_set(p.value, self.sk.p)
        mpz_set(q.value, self.sk.q)
        mpz_set(d.value, self.sk.d)
        mpz_set(dp.value, self.sk.dp)
        mpz_set(dq.value, self.sk.dq)
        mpz_set(q_inv.value, self.sk.q_inv)
        return RSAPrivateKey(n, p, q, d, dp, dq, q_inv)

    @cython.ccall
    def keygen(self) -> cython.void:
        if self.has_key:
            rsa_free_keys(cython.address(self.sk), cython.address(self.pk))
            self.has_key = False
        check(rsa_keygen(cython.address(self.sk), cython.address(self.pk), cython.address(self.pp)))
        self.has_key = True

    def _require_key(self):
        if not self.has_key:
            raise CryptoError(0, "Generate a key first")

    @cython.ccall
    def encrypt(self, m: bytes) -> bytes:
        self._require_key()
        if self.variant == RSAVariant.TEXTBOOK.value:
            tmp = GMPInteger()
            bytes_to_bigint(tmp.value, cython.cast(cython.p_uchar, m), len(m), BIG)
            check(rsa_encrypt(tmp.value, tmp.value, cython.address(self.pk)))
            return _to_bytes(tmp)

        k = rsa_modulus_size(self.pk.n)
        c = cython.cast(cython.p_uchar, malloc(k))
        if self.variant == RSAVariant.PKCS1.value:
            status = rsa_encrypt_pkcs1(c, cython.cast(cython.p_uchar, m), len(m), cython.address(self.pk))
        else:
            status = rsa_encrypt_oaep(c, cython.cast(cython.p_uchar, m), len(m), cython.address(self.pk), self.sec_level)
        result = cython.declare(bytes, c[:k])
        free(c)
        check(status)
        return result

    @cython.ccall
    def decrypt(self, c: bytes, algo: RSAAlgo) -> bytes:
        self._require_key()
        if self.variant == RSAVariant.TEXTBOOK.value:
            tmp = GMPInteger()
            bytes_to_bigint(tmp.value, cython.cast(cython.p_uchar, c), len(c), BIG)
            check(rsa_decrypt(tmp.value, tmp.value, cython.address(self.sk), algo.value))
            return _to_bytes(tmp)

        k = rsa_modulus_size(self.sk.n)
        m = cython.cast(cython.p_uchar, malloc(k))
        m_len: cython.size_t = 0
        if self.variant == RSAVariant.PKCS1.value:
            status = rsa_decrypt_pkcs1(m, cython.address(m_len), cython.cast(cython.p_uchar, c), len(c), cython.address(self.sk), algo.value)
        else:
            status = rsa_decrypt_oaep(m, cython.address(m_len), cython.cast(cython.p_uchar, c), len(c), cython.address(self.sk), algo.value, self.sec_level)
        result = cython.declare(bytes, m[:m_len])
        free(m)
        check(status)
        return result

    @cython.ccall
    def sign(self, m: bytes, algo: RSAAlgo) -> bytes:
        self._require_key()
        if self.variant == RSAVariant.TEXTBOOK.value:
            tmp = GMPInteger()
            bytes_to_bigint(tmp.value, cython.cast(cython.p_uchar, m), len(m), BIG)
            check(rsa_sign(tmp.value, tmp.value, cython.address(self.sk), algo.value))
            return _to_bytes(tmp)

        k = rsa_modulus_size(self.sk.n)
        s = cython.cast(cython.p_uchar, malloc(k))
        if self.variant == RSAVariant.PKCS1.value:
            status = rsa_sign_pkcs1(s, cython.cast(cython.p_uchar, m), len(m), cython.address(self.sk), algo.value, self.sec_level)
        else:
            status = rsa_sign_pss(s, cython.cast(cython.p_uchar, m), len(m), cython.address(self.sk), algo.value, self.sec_level)
        result = cython.declare(bytes, s[:k])
        free(s)
        check(status)
        return result

    @cython.ccall
    def verify(self, m: bytes, s: bytes):
        self._require_key()
        if self.variant == RSAVariant.TEXTBOOK.value:
            tmp_m = GMPInteger()
            tmp_s = GMPInteger()
            bytes_to_bigint(tmp_m.value, cython.cast(cython.p_uchar, m), len(m), BIG)
            bytes_to_bigint(tmp_s.value, cython.cast(cython.p_uchar, s), len(s), BIG)
            return bool(check_verify(rsa_verify(tmp_m.value, tmp_s.value, cython.address(self.pk))))

        if self.variant == RSAVariant.PKCS1.value:
            status = rsa_verify_pkcs1(cython.cast(cython.p_uchar, m), len(m), cython.cast(cython.p_uchar, s), len(s), cython.address(self.pk), self.sec_level)
        else:
            status = rsa_verify_pss(cython.cast(cython.p_uchar, m), len(m), cython.cast(cython.p_uchar, s), len(s), cython.address(self.pk), self.sec_level)
        return bool(check_verify(status))

def _to_bytes(n: GMPInteger) -> bytes:
    """Minimal big-endian encoding of a GMP integer."""
    value = int(n.get_value(16), 16)
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
