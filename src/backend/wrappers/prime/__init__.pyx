from wrappers.gmp cimport GMPInteger, mpz_t, gmp_randstate_t
from wrappers.rng cimport GMPState
from wrappers.enum cimport PrimalityTest

cdef extern from "prime_test.h":
    int primality_test(mpz_t, gmp_randstate_t, int, PrimalityTest)

cdef extern from "prime_gen.h":
    void gen_prime_b(mpz_t, gmp_randstate_t, int, int, int, PrimalityTest);
    void gen_prime_m(mpz_t, gmp_randstate_t, mpz_t, int, int, PrimalityTest);

cdef class Prime:

    def test(self, GMPInteger n, GMPState state, int reps, PrimalityTest test):
        return primality_test(n.value, state.state, reps, test)

    def gen_prime_b(self, GMPInteger n, GMPState state, int reps, int bit_size, int safe, PrimalityTest test):
        gen_prime_b(n.value, state.state, reps, bit_size, safe, test)
        return n.get_value(10)

    def gen_prime_m(self, GMPInteger n, GMPState state, GMPInteger m, int reps, int safe, PrimalityTest test):
        gen_prime_m(n.value, state.state, m.value, reps, safe, test)
        return n.get_value(10)