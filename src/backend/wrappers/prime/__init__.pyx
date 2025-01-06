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

    def test(self, GMPInteger n, GMPState state, int reps, test: PrimalityTest):
        return primality_test(n.value, state.state, reps, test.value)

    def gen_prime_b(self, GMPInteger n, GMPState state, int reps, int bit_size, int safe, test: PrimalityTest):
        gen_prime_b(n.value, state.state, reps, bit_size, safe, test.value)
        return n.get_value(10)

    def gen_prime_m(self, GMPInteger n, GMPState state, GMPInteger m, int reps, int safe, test: PrimalityTest):
        gen_prime_m(n.value, state.state, m.value, reps, safe, test.value)
        return n.get_value(10)