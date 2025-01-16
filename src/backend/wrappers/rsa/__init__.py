import cython
from enum import Enum
from wrappers.enums import SecurityLevel
from wrappers.gmp import GMPInteger

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
        setup(cython.address(self.pp), sec_level.value)
        self.sec_level = sec_level.value
        self.variant = variant.value

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
        keygen(cython.address(self.sk), cython.address(self.pk), self.pp)

    @cython.ccall
    def encrypt(self, m: bytes) -> bytes:
        tmp = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)
        bytes_to_bigint(tmp.value, buf, buf_len, BIG)

        if self.variant == RSAVariant.TEXTBOOK.value:
            crypto_encrypt(tmp.value, tmp.value, cython.address(self.pk))
        elif self.variant == RSAVariant.PKCS1.value:
            crypto_encrypt_pkcs1(tmp.value, tmp.value, cython.address(self.pk))
        elif self.variant == RSAVariant.SECURE.value:
            crypto_encrypt_oaep(tmp.value, tmp.value, cython.address(self.pk), self.sec_level)
        else:
            raise ValueError("Invalid RSA variant")

        c = cython.cast(cython.p_uchar, malloc(count_bytes(tmp.value)))
        c_len: cython.size_t = 0
        bigint_to_bytes(c, cython.address(c_len), tmp.value, BIG)

        result = cython.declare(bytes, c[:c_len])
        del tmp
        free(c)
        return result
    
    @cython.ccall
    def decrypt(self, c: bytes, algo: RSAAlgo) -> bytes:
        tmp = GMPInteger()

        buf = cython.cast(cython.p_uchar, c)
        buf_len = len(c)
        bytes_to_bigint(tmp.value, buf, buf_len, BIG)

        if self.variant == RSAVariant.TEXTBOOK.value:
            crypto_decrypt(tmp.value, tmp.value, cython.address(self.sk), algo.value)
        elif self.variant == RSAVariant.PKCS1.value:
            crypto_decrypt_pkcs1(tmp.value, tmp.value, cython.address(self.sk), algo.value)
        elif self.variant == RSAVariant.SECURE.value:
            crypto_decrypt_oaep(tmp.value, tmp.value, cython.address(self.sk), algo.value, self.sec_level)
        else:
            raise ValueError("Invalid RSA variant")

        m = cython.cast(cython.p_uchar, malloc(count_bytes(tmp.value)))
        m_len: cython.size_t = 0
        bigint_to_bytes(m, cython.address(m_len), tmp.value, BIG)

        result = cython.declare(bytes, m[:m_len])
        del tmp
        free(m)
        return result
    
    @cython.ccall
    def sign(self, m: bytes, algo: RSAAlgo) -> bytes:
        tmp = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)
        bytes_to_bigint(tmp.value, buf, buf_len, BIG)

        if self.variant == RSAVariant.TEXTBOOK.value:
            crypto_sign(tmp.value, tmp.value, cython.address(self.sk), algo.value)
        elif self.variant == RSAVariant.PKCS1.value:
            crypto_sign_pkcs1(tmp.value, tmp.value, cython.address(self.sk), algo.value, self.sec_level)
        elif self.variant == RSAVariant.SECURE.value:
            crypto_sign_pss(tmp.value, tmp.value, cython.address(self.sk), algo.value, self.sec_level)
        else:
            raise ValueError("Invalid RSA variant")

        s = cython.cast(cython.p_uchar, malloc(count_bytes(tmp.value)))
        s_len: cython.size_t = 0
        bigint_to_bytes(s, cython.address(s_len), tmp.value, BIG)

        result = cython.declare(bytes, s[:s_len])
        del tmp
        free(s)
        return result
    
    @cython.ccall
    def verify(self, m: bytes, s: bytes):
        tmp_m = GMPInteger()
        tmp_s = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)
        bytes_to_bigint(tmp_m.value, buf, buf_len, BIG)

        buf = cython.cast(cython.p_uchar, s)
        buf_len = len(s)
        bytes_to_bigint(tmp_s.value, buf, buf_len, BIG)
        
        result = 0
        if self.variant == RSAVariant.TEXTBOOK.value:
            result = crypto_verify(tmp_m.value, tmp_s.value, cython.address(self.pk))
        elif self.variant == RSAVariant.PKCS1.value:
            result = crypto_verify_pkcs1(tmp_m.value, tmp_s.value, cython.address(self.pk), self.sec_level)
        elif self.variant == RSAVariant.SECURE.value:
            result = crypto_verify_pss(tmp_m.value, tmp_s.value, cython.address(self.pk), self.sec_level)
        else:
            raise ValueError("Invalid RSA variant")
        
        del tmp_m, tmp_s
        return bool(result)