from libc.stdlib cimport malloc, free

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
    void mpz_set(mpz_t, mpz_t)
    void mpz_set_ui(mpz_t, unsigned long int)
    void mpz_set_str(mpz_t, const char *str, int)
    void mpz_get_str(char *, int, mpz_t)
    unsigned long int mpz_get_ui(const mpz_t)
    void gmp_randinit_default(gmp_randstate_t)
    void gmp_randseed_ui(gmp_randstate_t, unsigned long int)
    void gmp_randclear(gmp_randstate_t)

# Expose the GMPInteger class
cdef class GMPInteger:
    cdef mpz_t value

    cpdef set_value(self, str value, int base)
    cpdef get_value(self, int base)
