import cython
from wrappers.enums import PrimalityTest
from wrappers.gmp import GMPInteger
from wrappers.rng import GMPState

@cython.cclass
class Prime:
    @cython.ccall
    def test(self, n: GMPInteger, state: GMPState, reps: cython.int, test: PrimalityTest):
        return bool(primality_test(n.value, state.state, reps, test.value))

    @cython.ccall
    def gen_prime_b(self, state: GMPState, reps: cython.int, bit_size: cython.int, safe: cython.int, test: PrimalityTest) -> str:
        n = GMPInteger()
        gen_prime_b(n.value, state.state, reps, bit_size, safe, test.value)
        return n.get_value(10)

    @cython.ccall
    def gen_prime_m(self, state: GMPState, m: GMPInteger, reps: cython.int, safe: cython.int, test: PrimalityTest) -> str:
        n = GMPInteger()
        gen_prime_m(n.value, state.state, m.value, reps, safe, test.value)
        return n.get_value(10)