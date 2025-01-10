import cython
from wrappers.ec import EC, ECP
from wrappers.enums import HashFunction
from wrappers.gmp import GMPInteger

class ECDSAPublicParams:
    def __init__(self, curve: EC):
        self.curve = curve
        
class ECDSAPublicKey:
    def __init__(self, q: ECP):
        self.q = q

class ECDSAPrivateKey:
    def __init__(self, d: GMPInteger):
        self.d = d
        
@cython.cclass
class ECDSA:
    def __init__(self, curve: EC):
        setup(cython.address(self.pp), curve.curve_type.value, curve.curve_id.value)
        self.curve = curve
    
    @property
    def params(self) -> ECDSAPublicParams:
        return ECDSAPublicParams(self.curve)
    
    @property
    def pubKey(self) -> ECDSAPublicKey:
        q = ECP(self.curve)
        copy_point(cython.address(q.p), self.pk.Q)
        return ECDSAPublicKey(q)
    
    @property
    def prvKey(self) -> ECDSAPrivateKey:
        d = GMPInteger()
        mpz_set(d.value, self.sk.d)
        return ECDSAPrivateKey(d)
    
    @cython.ccall
    def keygen(self) -> cython.void:
        keygen(cython.address(self.sk), cython.address(self.pk), cython.address(self.pp))
        
    @cython.ccall
    def sign(self, m: bytes, hash_func: HashFunction):
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()
        
        crypto_sign(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), \
            cython.address(self.sk), cython.address(self.pp), hash_func.value)
        
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
        
        result = crypto_verify(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), \
            len(m), cython.address(self.pk), cython.address(self.pp), hash_func.value)
        del tmp1, tmp2
        return bool(result)