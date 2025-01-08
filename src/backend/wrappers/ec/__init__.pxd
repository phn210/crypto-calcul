from libc.stdlib cimport malloc, free
from wrappers.gmp cimport GMPInteger, mpz_t, mpz_set

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
        int cof
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


cdef class EC:
    cdef curve_t curve
    cdef public curve_type, curve_id

    cpdef ECP generator(self)
    cpdef ECP infinity(self)
    cpdef is_infinity(self, ECP p)
    cpdef is_on_curve(self, ECP p)
    cpdef equals(self, ECP p, ECP q)
    cpdef ECP neg(self, ECP p)
    cpdef ECP add(self, ECP p, ECP q)
    cpdef ECP dadd(self, ECP p, ECP q, ECP w)
    cpdef ECP dbl(self, ECP p)
    cpdef ECP mul(self, ECP p, GMPInteger k)
    cpdef bytes point_to_bytes(self, ECP p)
    cpdef ECP point_from_bytes(self, bytes buf)


cdef class ECP:
    cdef point_t p
    cdef EC ec
    
    cpdef is_generator(self)
    cpdef is_infinity(self)
    cpdef is_on_curve(self)
    cpdef ECP neg(self)
    cpdef ECP add(self, ECP q)
    cpdef ECP dadd(self, ECP q, ECP w)
    cpdef ECP dbl(self)
    cpdef ECP mul(self, GMPInteger k)