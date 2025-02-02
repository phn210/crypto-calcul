import cython
from wrappers.ec import EC
from wrappers.gmp import GMPInteger

@cython.cclass
class ECDH:
    def __init__(self, curve: EC):
        setup(cython.address(self.pp), curve.curve_type.value, curve.curve_id.value)
        
    @cython.ccall
    def gen_secret(self) -> bytes:
        s = GMPInteger()
        gen_secret(s.value, cython.address(self.pp))
        
        secret = cython.cast(cython.p_uchar, malloc(count_bytes(s.value)))
        secret_len: cython.size_t = 0
        bigint_to_bytes(secret, cython.address(secret_len), s.value, BIG)
        
        result = cython.declare(bytes, secret[:secret_len])
        del s
        free(secret)
        return result
    
    @cython.ccall
    def gen_public(self, secret: bytes) -> bytes:
        s = GMPInteger()
        p = GMPInteger()
        
        bytes_to_bigint(s.value, cython.cast(cython.p_uchar, secret), len(secret), BIG)
        gen_public(p.value, s.value, cython.address(self.pp))
        
        public = cython.cast(cython.p_uchar, malloc(count_bytes(p.value)))
        public_len: cython.size_t = 0
        bigint_to_bytes(public, cython.address(public_len), p.value, BIG)
        
        result = cython.declare(bytes, public[:public_len])
        del s, p
        free(public)
        return result

    @cython.ccall
    def compute_shared_secret(self, secret: bytes, public: bytes) -> bytes:
        s = GMPInteger()
        p = GMPInteger()
        ss = GMPInteger()
        
        bytes_to_bigint(s.value, cython.cast(cython.p_uchar, secret), len(secret), BIG)
        bytes_to_bigint(p.value, cython.cast(cython.p_uchar, public), len(public), BIG)
        compute_shared_secret(ss.value, s.value, p.value, cython.address(self.pp))
        
        shared = cython.cast(cython.p_uchar, malloc(count_bytes(ss.value)))
        shared_len: cython.size_t = 0
        bigint_to_bytes(shared, cython.address(shared_len), ss.value, BIG)
        
        result = cython.declare(bytes, shared[:shared_len])
        del s, p, ss
        free(shared)
        return result