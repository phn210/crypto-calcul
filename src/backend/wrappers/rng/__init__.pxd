from wrappers.gmp cimport *

cdef extern from "rng.h":
    void rng_init(gmp_randstate_t)
    void rng_init_with_seed(gmp_randstate_t, unsigned int)
    void rand_int_b(mpz_t, gmp_randstate_t, unsigned long)
    void rand_int_m(mpz_t, gmp_randstate_t, mpz_t)
    void rand_bytes(char *, gmp_randstate_t, unsigned int)

cdef class GMPState:
    cdef gmp_randstate_t state

    cpdef seed(self, unsigned int seed)
