import cython
from wrappers.ec import EC, ECP
from wrappers.enums import HashFunction
from wrappers.gmp import GMPInteger
from wrappers.enums import CryptoError

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
        check(ecelgamal_setup(cython.address(self.pp), curve.curve_type.value, curve.curve_id.value))
        self.has_params = True
        self.curve = curve

    def __dealloc__(self):
        if self.has_key:
            ecelgamal_free_keys(cython.address(self.sk), cython.address(self.pk))
        if self.has_params:
            ecelgamal_free_params(cython.address(self.pp))

    def _require_key(self):
        if not self.has_key:
            raise CryptoError(0, "Generate a key first")

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
        if self.has_key:
            ecelgamal_free_keys(cython.address(self.sk), cython.address(self.pk))
            self.has_key = False
        check(ecelgamal_keygen(cython.address(self.sk), cython.address(self.pk), cython.address(self.pp)))
        self.has_key = True

    @cython.ccall
    def encrypt(self, m: bytes, hash_func: HashFunction):
        self._require_key()
        c1_len = point_size(self.pp.curve)
        c1 = cython.cast(cython.p_uchar, malloc(c1_len))
        c2 = cython.cast(cython.p_uchar, malloc(len(m) + 1))
        status = ecelgamal_encrypt(c1, c2, cython.cast(cython.p_uchar, m), len(m),
            cython.address(self.pk), cython.address(self.pp), hash_func.value)
        result = [cython.cast(bytes, c1[:c1_len]), cython.cast(bytes, c2[:len(m)])]
        free(c1)
        free(c2)
        check(status)
        return result

    @cython.ccall
    def decrypt(self, c1: bytes, c2: bytes, hash_func: HashFunction) -> bytes:
        self._require_key()
        m = cython.cast(cython.p_uchar, malloc(len(c2) + 1))
        status = ecelgamal_decrypt(m, cython.cast(cython.p_uchar, c1), len(c1), cython.cast(cython.p_uchar, c2), len(c2),
            cython.address(self.sk), cython.address(self.pp), hash_func.value)
        result = cython.declare(bytes, m[:len(c2)])
        free(m)
        check(status)
        return result

    @cython.ccall
    def sign(self, m: bytes, hash_func: HashFunction):
        self._require_key()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        check(ecelgamal_sign(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), cython.address(self.sk), cython.address(self.pp), hash_func.value))

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
        self._require_key()
        tmp1 = GMPInteger()
        tmp2 = GMPInteger()

        bytes_to_bigint(tmp1.value, cython.cast(cython.p_uchar, s), len(s), BIG)
        bytes_to_bigint(tmp2.value, cython.cast(cython.p_uchar, r), len(r), BIG)

        result = check_verify(ecelgamal_verify(tmp1.value, tmp2.value, cython.cast(cython.p_uchar, m), len(m), cython.address(self.pk), cython.address(self.pp), hash_func.value))
        del tmp1, tmp2
        return bool(result)
