from libc.stdlib cimport malloc, free
from wrappers.gmp cimport GMPInteger, mpz_t, mpz_init, mpz_clear, mpz_set, mpz_set_ui, mpz_get_ui
from wrappers.enums import EC as ECType, WeierstrassCurve, MontgomeryCurve, EdwardsCurve
from dataclasses import dataclass

cdef extern from "ec.h":
    ctypedef struct point:
        mpz_t x
        mpz_t y
        mpz_t z
    ctypedef point point_t

    ctypedef struct point_affine:
        mpz_t x
        mpz_t y
    ctypedef point_affine point_affine_t

    ctypedef struct curve:
        char *name
        int cof;
        size_t efs
        mpz_t p
        mpz_t r
        mpz_t a
        mpz_t b
        pass
    ctypedef curve curve_t

    void init_point(point_t *);
    void free_point(point_t *);
    void copy_point(point_t *, const point_t);
    void swap_points(point_t *, point_t *);

    void init_affine(point_affine_t *);
    void free_affine(point_affine_t *);
    void copy_affine(point_affine_t *, const point_affine_t);

    void init_curve(curve_t *, unsigned char, unsigned char);
    void free_curve(curve_t *);

    void rhs(mpz_t, const mpz_t, const curve_t);
    void generator(point_t *, const curve_t);
    void infinity(point_t *, const curve_t);
    char is_infinity(const point_t, const curve_t);
    char is_on_curve(const point_t, const curve_t);
    char equals(const point_t, const point_t, const curve_t);
    void neg(point_t *, const point_t, const curve_t);
    void add(point_t *, const point_t, const point_t, const curve_t);
    void dadd(point_t *, const point_t, const point_t, const point_t, const curve_t);
    void dbl(point_t *, const point_t, const curve_t);
    void mul(point_t *, const point_t, const mpz_t, const curve_t);
    void point_to_bytes(unsigned char *, const point_t, const curve_t);
    void point_from_bytes(point_t *, const unsigned char *, const curve_t);


@dataclass
class CurveInfo:
    name: str
    cof: int
    efs: int
    p: int
    r: int
    a: int
    b: int


cdef class EC:

    cdef curve_t curve
    cdef public curve_type, curve_id

    def __init__(self, curve_type: ECType, curve_id: WeierstrassCurve | MontgomeryCurve | EdwardsCurve):
        self.curve_type = curve_type
        self.curve_id = curve_id
        init_curve(&self.curve, self.curve_type.value, self.curve_id.value)

    def __dealloc__(self):
        free_curve(&self.curve)

    def __eq__(self, other):
        if not isinstance(other, EC):
            return False
        return self.curve_type == other.curve_type and self.curve_id == other.curve_id
    
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __copy__(self):
        return EC(self.curve_type, self.curve_id)

    def info(self):
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
            int(p.get_value(10)),
            int(r.get_value(10)),
            int(a.get_value(10)),
            int(b.get_value(10))
        )
    
    cpdef generator(self):
        cdef ECP r = ECP(self)
        generator(&r.p, self.curve)
        return r
    
    cpdef infinity(self):
        cdef ECP r = ECP(self)
        infinity(&r.p, self.curve)
        return r
    
    cpdef is_infinity(self, ECP p):
        return bool(is_infinity(p.p, self.curve))
    
    cpdef is_on_curve(self, ECP p):
        return bool(is_on_curve(p.p, self.curve))
    
    cpdef equals(self, ECP p, ECP q):
        return bool(equals(p.p, q.p, self.curve))
    
    cpdef neg(self, ECP p):
        cdef ECP r = ECP(self)
        neg(&r.p, p.p, self.curve)
        return r

    cpdef add(self, ECP p, ECP q):
        cdef ECP r = ECP(self)
        add(&r.p, p.p, q.p, self.curve)
        return r

    cpdef dadd(self, ECP p, ECP q, ECP w):
        cdef ECP r = ECP(self)
        dadd(&r.p, p.p, q.p, w.p, self.curve)
        return r
    
    cpdef dbl(self, ECP p):
        cdef ECP r = ECP(self)
        dbl(&r.p, p.p, self.curve)
        return r
    
    cpdef mul(self, ECP p, int k):
        cdef mpz_t k_mpz
        mpz_init(k_mpz)
        mpz_set_ui(k_mpz, k)
        cdef ECP r = ECP(self)
        mul(&r.p, p.p, k_mpz, self.curve)
        mpz_clear(k_mpz)
        return r
    
    cpdef point_to_bytes(self, ECP p):
        len_byte = self.info().efs if self.curve_type == ECType.MONTGOMERY else self.info().efs * 2
        cdef unsigned char *buf = <unsigned char *> malloc(len_byte)
        point_to_bytes(buf, p.p, self.curve)
        result = bytes(buf[:len_byte])
        free(buf)
        return result
    
    cpdef point_from_bytes(self, bytes buf):
        cdef ECP r = ECP(self)
        point_from_bytes(&r.p, buf, self.curve)
        return r


cdef class ECP:

    cdef point_t p
    cdef EC ec

    def __cinit__(self, EC ec):
        init_point(&self.p)
        self.ec = ec
    
    def __dealloc__(self):
        free_point(&self.p)
    
    def __eq__(self, other):
        if not isinstance(other, ECP):
            return False
        return self.ec.equals(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __copy__(self):
        return ECP(self.ec)

    def __str__(self):
        return self.ec.point_to_bytes(self).hex()[2:]

    def __bytes__(self):
        return self.ec.point_to_bytes(self)

    def __mul__(self, int k):
        return self.ec.mul(self, k)
    
    def __neg__(self):
        return self.ec.neg(self)

    def __add__(self, other):
        return self.ec.add(self, other)

    def __getitem__(self, int i):
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

    def neg(self):
        return -self

    def add(self, ECP q):
        return self + q
    
    def dadd(self, ECP q, ECP w):
        return self.ec.dadd(self, q, w)

    def dbl(self):
        return self.ec.dbl(self)

    def mul(self, int k):
        return self * k


cdef class P224(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P224)

cdef class P256(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P256)

cdef class P384(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P384)

cdef class P521(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P521)

cdef class SECP256K1(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.P256K1)

cdef class W25519(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.W25519)

cdef class W448(EC):
    def __init__(self):
        super().__init__(ECType.WEIERSTRASS, WeierstrassCurve.W448)

cdef class C25519(EC):
    def __init__(self):
        super().__init__(ECType.MONTGOMERY, MontgomeryCurve.C25519)

cdef class C448(EC):
    def __init__(self):
        super().__init__(ECType.MONTGOMERY, MontgomeryCurve.C448)

cdef class ED25519(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.ED25519)

cdef class ED448(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.ED448)

cdef class E448(EC):
    def __init__(self):
        super().__init__(ECType.EDWARDS, EdwardsCurve.E448)