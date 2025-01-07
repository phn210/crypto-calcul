from wrappers.gmp cimport GMPInteger, mpz_t, gmp_randstate_t
from wrappers.rng cimport GMPState
from wrappers.enums import PrimalityTest

cdef extern from "prime_test.h":
    ctypedef enum prime_test_t:
        pass
    int primality_test(mpz_t, gmp_randstate_t, int, prime_test_t)

cdef extern from "prime_gen.h":
    void gen_prime_b(mpz_t, gmp_randstate_t, int, int, int, prime_test_t);
    void gen_prime_m(mpz_t, gmp_randstate_t, mpz_t, int, int, prime_test_t);

cdef class Prime:
    cpdef test(self, GMPInteger n, GMPState state, int reps, test: PrimalityTest)
    cpdef str gen_prime_b(self, GMPState state, int reps, int bit_size, int safe, test: PrimalityTest)
    cpdef str gen_prime_m(self, GMPState state, GMPInteger m, int reps, int safe, test: PrimalityTest)