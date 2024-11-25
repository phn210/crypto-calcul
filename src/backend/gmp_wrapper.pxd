cdef extern from "stdlib.h":
    void *malloc(size_t size)
    void free(void *ptr)

cdef extern from "gmp.h":
    # GMP Integer and Random State Structures
    ctypedef struct __mpz_struct:
        pass
    ctypedef __mpz_struct mpz_t

    ctypedef struct __gmp_randstate_struct:
        pass
    ctypedef __gmp_randstate_struct gmp_randstate_t

    # GMP Functions
    void mpz_init(mpz_t)
    void mpz_clear(mpz_t)
    void mpz_get_str(char *, int, mpz_t)
    void mpz_set_str(mpz_t rop, const char *str, int base)

# Expose the GMPInteger class
cdef class GMPInteger:
    cdef mpz_t value

    cdef set_value(self, str value, int base)
    cdef get_value(self, int base)
