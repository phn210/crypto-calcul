import cython
from wrappers.enums import SecurityLevel, HashFunction
from wrappers.gmp import GMPInteger

class DSAPublicParams:
    def __init__(self, p_bits: int, q_bits: int, p: GMPInteger, q: GMPInteger, g: GMPInteger):
        self.p_bits = p_bits
        self.q_bits = q_bits
        self.p = p
        self.q = q
        self.g = g
        
class DSAPublicKey:
    def __init__(self, y: GMPInteger):
        self.y = y
        
class DSAPrivateKey:
    def __init__(self, x: GMPInteger):
        self.x = x
        
@cython.cclass
class DSA:
    def __init__(self, sec_level: SecurityLevel, hash_function: HashFunction):
        setup(cython.address(self.pp), sec_level.value, hash_function.value)
    
    @property
    def params(self) -> DSAPublicParams:
        p = GMPInteger()
        q = GMPInteger()
        g = GMPInteger()
        mpz_set(p.value, self.pp.p)
        mpz_set(q.value, self.pp.q)
        mpz_set(g.value, self.pp.g)
        return DSAPublicParams(self.pp.p_bits, self.pp.q_bits, p, q, g)
    
    @property
    def pubKey(self) -> DSAPublicKey:
        y = GMPInteger()
        mpz_set(y.value, self.pk.y)
        return DSAPublicKey(y)
    
    @property
    def prvKey(self) -> DSAPrivateKey:
        x = GMPInteger()
        mpz_set(x.value, self.sk.x)
        return DSAPrivateKey(x)
    
    @cython.ccall
    def keygen(self) -> cython.void:
        keygen(cython.address(self.sk), cython.address(self.pk), self.pp)
    
    @cython.ccall
    def sign(self, m: bytes):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()
        
        crypto_sign(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), self.sk, self.pp)

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
        
        bytes_to_bigint(tmp1.value, cython.cast(cython.p_uchar, s), len(s), BIG)
        bytes_to_bigint(tmp2.value, cython.cast(cython.p_uchar, r), len(r), BIG)
        
        result = crypto_verify(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), self.pk, self.pp)
        del tmp1, tmp2
        return bool(result)