from wrappers.gmp cimport malloc, free, gmp_randstate_t, mpz_t, GMPInteger
from wrappers.enums cimport cc_status_t, check

cdef extern from "rng.h":
    cc_status_t rng_init(gmp_randstate_t)
    void rng_init_with_seed(gmp_randstate_t, unsigned int)
    void rand_int_b(mpz_t, gmp_randstate_t, unsigned long)
    cc_status_t rand_int_m(mpz_t, gmp_randstate_t, mpz_t)
    void rand_bytes(char *, gmp_randstate_t, unsigned int)

cdef class GMPState:
    cdef gmp_randstate_t state

    cpdef seed(self, unsigned int seed)

cdef class RNG:
    cdef public GMPState state

    cpdef str rand_int_b(self, unsigned long bits, int base)
    cpdef str rand_int_m(self, GMPInteger modulo, int base)
    cpdef bytes rand_bytes(self, int byte_len)

