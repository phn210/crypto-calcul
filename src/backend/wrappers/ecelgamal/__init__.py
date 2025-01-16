import cython
from wrappers.ec import EC, ECP
from wrappers.enums import HashFunction
from wrappers.gmp import GMPInteger

class ECElGamalPublicParams:
    def __init__(self, curve: EC):
        self.curve = curve
        
class ECElGamalPublicKey:
    def __init__(self, y: ECP):
        self.y = y

class ECElGamalPrivateKey:
    def __init__(self, x: GMPInteger):
        self.x = x
        
@cython.cclass
class ECElGamal:
    def __init__(self, curve: EC):
        setup(cython.address(self.pp), curve.curve_type.value, curve.curve_id.value)
        self.curve = curve
        
    @property
    def params(self) -> ECElGamalPublicParams:
        return ECElGamalPublicParams(self.curve)
    
    @property
    def pubKey(self) -> ECElGamalPublicKey:
        y = ECP(self.curve)
        copy_point(cython.address(y.p), self.pk.Y)
        return ECElGamalPublicKey(y)
    
    @property
    def prvKey(self) -> ECElGamalPrivateKey:
        x = GMPInteger()
        mpz_set(x.value, self.sk.x)
        return ECElGamalPrivateKey(x)
    
    @cython.ccall
    def keygen(self) -> cython.void:
        keygen(cython.address(self.sk), cython.address(self.pk), cython.address(self.pp))
        
    @cython.ccall
    def encrypt(self, m: bytes, hash_func: HashFunction):
        tmp = GMPInteger()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        bytes_to_bigint(tmp.value, cython.cast(cython.p_uchar, m), len(m), BIG)
        crypto_encrypt(tmp1.value, tmp2.value, tmp.value, cython.address(self.pk), cython.address(self.pp), hash_func.value)

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
    def decrypt(self, c1: bytes, c2: bytes, hash_func: HashFunction) -> bytes:
        tmp = GMPInteger()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        bytes_to_bigint(tmp1.value, cython.cast(cython.p_uchar, c1), len(c1), BIG)
        bytes_to_bigint(tmp2.value, cython.cast(cython.p_uchar, c2), len(c2), BIG)
        crypto_decrypt(tmp.value, tmp1.value, tmp2.value, cython.address(self.sk), cython.address(self.pp), hash_func.value)

        m = cython.cast(cython.p_uchar, malloc(count_bytes(tmp.value)))
        m_len: cython.size_t = 0
        bigint_to_bytes(m, cython.address(m_len), tmp.value, BIG)
        
        result = cython.declare(bytes, m[:m_len])
        del tmp, tmp1, tmp2
        free(m)
        return result
    
    @cython.ccall
    def sign(self, m: bytes, hash_func: HashFunction):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()
        
        crypto_sign(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), cython.address(self.sk), cython.address(self.pp), hash_func.value)

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
    def verify(self, m: bytes, s: bytes, r: bytes, hash_func: HashFunction):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()
        
        bytes_to_bigint(tmp1.value, cython.cast(cython.p_uchar, s), len(s), BIG)
        bytes_to_bigint(tmp2.value, cython.cast(cython.p_uchar, r), len(r), BIG)
        
        result = crypto_verify(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), cython.address(self.pk), cython.address(self.pp), hash_func.value)
        del tmp1, tmp2
        return bool(result)