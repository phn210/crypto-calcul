import cython
from dataclasses import dataclass
from enum import Enum
from typing import Self
from wrappers.gmp import GMPInteger

class ECType(Enum):
    WEIERSTRASS = _WEIERSTRASS
    MONTGOMERY = _MONTGOMERY
    EDWARDS = _EDWARDS

class WeierstrassCurve(Enum):
    P224 = _P224
    P256 = _P256
    P384 = _P384
    P521 = _P521
    P256K1 = _P256K1
    W25519 = _W25519
    W448 = _W448

class MontgomeryCurve(Enum):
    C25519 = _C25519
    C448 = _C448

class EdwardsCurve(Enum):
    ED25519 = _ED25519
    ED448 = _ED448
    E448 = _E448

@dataclass
class CurveInfo:
    name: str
    cof: int
    efs: int
    p: GMPInteger
    r: GMPInteger
    a: GMPInteger
    b: GMPInteger


@cython.cclass
class ECP:
    def __init__(self, ec: EC):
        init_point(cython.address(self.p))
        self.ec = ec
    
    def __dealloc__(self):
        free_point(cython.address(self.p))
    
    def __eq__(self, other):
        if not isinstance(other, ECP):
            return False
        return self.ec.equals(self, other)

    def __ne__(self, other) -> Self:
        return not self.__eq__(other)

    def __copy__(self) -> Self:
        return ECP(self.ec)

    def __str__(self) -> str:
        return self.ec.point_to_bytes(self).hex()[2:]

    def __bytes__(self) -> bytes:
        return self.ec.point_to_bytes(self)

    def __mul__(self, k: GMPInteger | int) -> Self:
        if not isinstance(k, GMPInteger):
            k_mpz = GMPInteger()
            k_mpz.set_value(str(k), 10)
            return self.ec.mul(self, k_mpz)
        return self.ec.mul(self, k)
    
    def __neg__(self) -> Self:
        return self.ec.neg(self)

    def __add__(self, other) -> Self:
        return self.ec.add(self, other)

    def __getitem__(self, i: int):
        if i == 0:
            x = GMPInteger()
            mpz_set(x.value, self.p.x)
            return int(x.get_value(10))
        elif i == 1:
            y = GMPInteger()
            mpz_set(y.value, self.p.y)
            return int(y.get_value(10))
        elif i == 2:
            z = GMPInteger()
            mpz_set(z.value, self.p.z)
            return int(z.get_value(10))
        else:
            raise IndexError("Index out of range")
    
    def is_generator(self):
        return self == self.ec.generator()
    
    def is_infinity(self):
        return self.ec.is_infinity(self)

    def is_on_curve(self):
        return self.ec.is_on_curve(self)

    def neg(self) -> Self:
        return -self

    def add(self, q: ECP) -> Self:
        return self + q
    
    def dadd(self, q: ECP, w: ECP) -> Self:
        return self.ec.dadd(self, q, w)

    def dbl(self) -> Self:
        return self.ec.dbl(self)

    def mul(self, k: GMPInteger) -> Self:
        return self * k


@cython.cclass
class EC:
    def __init__(self, curve_type: ECType, curve_id: WeierstrassCurve | MontgomeryCurve | EdwardsCurve):
        self.curve_type = curve_type
        self.curve_id = curve_id
        init_curve(cython.address(self.curve), self.curve_type.value, self.curve_id.value)

    def __dealloc__(self):
        free_curve(cython.address(self.curve))

    def __eq__(self, other):
        if not isinstance(other, EC):
            return False
        return self.curve_type == other.curve_type and self.curve_id == other.curve_id
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __copy__(self):
        return EC(self.curve_type, self.curve_id)

    def info(self) -> CurveInfo:
        p = GMPInteger()
        r = GMPInteger()
        a = GMPInteger()
        b = GMPInteger()
        mpz_set(p.value, self.curve.p)
        mpz_set(r.value, self.curve.r)
        mpz_set(a.value, self.curve.a)
        mpz_set(b.value, self.curve.b)

        return CurveInfo(
            str(self.curve.name, 'utf-8'),
            int(self.curve.cof),
            int(self.curve.efs),
            p,
            r,
            a,
            b
        )
    
    @cython.ccall
    def generator(self) -> ECP:
        r = ECP(self)
        generator(cython.address(r.p), self.curve)
        return r
    
    @cython.ccall
    def infinity(self) -> ECP:
        r = ECP(self)
        infinity(cython.address(r.p), self.curve)
        return r
    
    @cython.ccall
    def is_infinity(self, p: ECP):
        return bool(is_infinity(p.p, self.curve))
    
    @cython.ccall
    def is_on_curve(self, p: ECP):
        return bool(is_on_curve(p.p, self.curve))
    
    @cython.ccall
    def equals(self, p: ECP, q: ECP):
        return bool(equals(p.p, q.p, self.curve))
    
    @cython.ccall
    def neg(self, p: ECP) -> ECP:
        r = ECP(self)
        neg(cython.address(r.p), p.p, self.curve)
        return r

    @cython.ccall
    def add(self, p: ECP, q: ECP) -> ECP:
        r = ECP(self)
        add(cython.address(r.p), p.p, q.p, self.curve)
        return r

    @cython.ccall
    def dadd(self, p: ECP, q: ECP, w: ECP) -> ECP:
        r = ECP(self)
        dadd(cython.address(r.p), p.p, q.p, w.p, self.curve)
        return r
    
    @cython.ccall
    def dbl(self, p: ECP) -> ECP:
        r = ECP(self)
        dbl(cython.address(r.p), p.p, self.curve)
        return r
    
    @cython.ccall
    def mul(self, p: ECP, k: GMPInteger) -> ECP:
        r = ECP(self)
        mul(cython.address(r.p), p.p, k.value, self.curve)
        return r
    
    @cython.ccall
    def point_to_bytes(self, p: ECP) -> bytes:
        len_byte = self.info().efs if self.curve_type == ECType.MONTGOMERY else self.info().efs * 2
        buf = cython.cast(cython.p_uchar, malloc(len_byte))
        point_to_bytes(buf, p.p, self.curve)
        result = cython.declare(bytes, buf[:len_byte])
        free(buf)
        return result
    
    @cython.ccall
    def point_from_bytes(self, buf: bytes) -> ECP:
        r = ECP(self)
        point_from_bytes(cython.address(r.p), buf, self.curve)
        return r


class P224(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P224)

class P256(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P256)

class P384(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P384)

class P521(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P521)

class SECP256K1(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P256K1)

class W25519(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.W25519)

class W448(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.W448)

class C25519(EC):
    def __init__(self):
        super().__init__(ECType.MONTGOMERY, MontgomeryCurve.C25519)

class C448(EC):
    def __init__(self):
        super().__init__(ECType.MONTGOMERY, MontgomeryCurve.C448)

class ED25519(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.ED25519)

class ED448(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.ED448)

class E448(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.E448)