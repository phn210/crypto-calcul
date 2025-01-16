import cython
from wrappers.enums import SecurityLevel
from wrappers.gmp import GMPInteger

class ElGamalPublicParams:
    def __init__(self, n_bits: int, p: GMPInteger, g: GMPInteger):
        self.n_bits = n_bits
        self.p = p
        self.g = g

class ElGamalPublicKey:
    def __init__(self, y: GMPInteger):
        self.y = y

class ElGamalPrivateKey:
    def __init__(self, x: GMPInteger):
        self.x = x

@cython.cclass
class ElGamal:
    def __init__(self, sec_level: SecurityLevel):
        setup(cython.address(self.pp), sec_level.value)
        self.sec_level = sec_level.value

    @property
    def params(self) -> ElGamalPublicParams:
        p = GMPInteger()
        g = GMPInteger()
        mpz_set(p.value, self.pp.p)
        mpz_set(g.value, self.pp.g)
        return ElGamalPublicParams(self.pp.p_bits, p, g)

    @property
    def pubKey(self) -> ElGamalPublicKey:
        y = GMPInteger()
        mpz_set(y.value, self.pk.y)
        return ElGamalPublicKey(y)
    
    @property
    def prvKey(self) -> ElGamalPrivateKey:
        x = GMPInteger()
        mpz_set(x.value, self.sk.x)
        return ElGamalPrivateKey(x)
    
    @cython.ccall
    def keygen(self) -> cython.void:
        keygen(cython.address(self.sk), cython.address(self.pk), cython.address(self.pp))

    @cython.ccall
    def encrypt(self, m: bytes):
        tmp = GMPInteger()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)
        bytes_to_bigint(tmp.value, buf, buf_len, BIG)
        crypto_encrypt(tmp1.value, tmp2.value, tmp.value, cython.address(self.pk), cython.address(self.pp))

        c1 = cython.cast(cython.p_uchar, malloc(count_bytes(tmp1.value)))
        c1_len: cython.size_t = 0
        bigint_to_bytes(c1, cython.address(c1_len), tmp1.value, BIG)

        c2 = cython.cast(cython.p_uchar, malloc(count_bytes(tmp2.value)))
        c2_len: cython.size_t = 0
        bigint_to_bytes(c2, cython.address(c2_len), tmp2.value, BIG)

        result = [cython.cast(bytes, c1[:c1_len]), cython.cast(bytes, c2[:c2_len])]
        del tmp, tmp1, tmp2
        free(c1)
        free(c2)
        return result
    
    @cython.ccall
    def decrypt(self, c1: bytes, c2: bytes) -> bytes:
        tmp = GMPInteger()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        buf1 = cython.cast(cython.p_uchar, c1)
        buf1_len = len(c1)
        bytes_to_bigint(tmp1.value, buf1, buf1_len, BIG)

        buf2 = cython.cast(cython.p_uchar, c2)
        buf2_len = len(c2)
        bytes_to_bigint(tmp2.value, buf2, buf2_len, BIG)

        crypto_decrypt(tmp.value, tmp1.value, tmp2.value, cython.address(self.sk), cython.address(self.pp))

        m = cython.cast(cython.p_uchar, malloc(count_bytes(tmp.value)))
        m_len: cython.size_t = 0
        bigint_to_bytes(m, cython.address(m_len), tmp.value, BIG)
        result = cython.declare(bytes, m[:m_len])
        del tmp, tmp1, tmp2
        free(m)
        return result
    
    @cython.ccall
    def sign(self, m: bytes):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)
        
        crypto_sign(tmp1.value, tmp2.value, buf, buf_len, cython.address(self.sk), cython.address(self.pp), self.sec_level)

        s = cython.cast(cython.p_uchar, malloc(count_bytes(tmp1.value)))
        s_len: cython.size_t = 0
        bigint_to_bytes(s, cython.address(s_len), tmp1.value, BIG)

        r = cython.cast(cython.p_uchar, malloc(count_bytes(tmp2.value)))
        r_len: cython.size_t = 0
        bigint_to_bytes(r, cython.address(r_len), tmp2.value, BIG)

        result = [cython.cast(bytes, s[:s_len]), cython.cast(bytes, r[:r_len])]
        del tmp1, tmp2
        free(s)
        free(r)
        return result
    
    @cython.ccall
    def verify(self, m: bytes, s: bytes, r: bytes):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        buf = cython.cast(cython.p_uchar, m)
        buf_len = len(m)

        buf1 = cython.cast(cython.p_uchar, s)
        buf1_len = len(s)
        bytes_to_bigint(tmp1.value, buf1, buf1_len, BIG)

        buf2 = cython.cast(cython.p_uchar, r)
        buf2_len = len(r)
        bytes_to_bigint(tmp2.value, buf2, buf2_len, BIG)

        result = crypto_verify(tmp1.value, tmp2.value, buf, buf_len, cython.address(self.pk), cython.address(self.pp), self.sec_level)
        del tmp1, tmp2
        return bool(result)