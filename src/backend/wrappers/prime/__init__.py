import cython
from enum import Enum
from wrappers.gmp import GMPInteger
from wrappers.rng import GMPState

class PrimalityTest(Enum):
    GMP = _GMP_TEST
    FERMAT = _FERMAT_TEST
    MILLER_RABIN = _MILLER_RABIN_TEST

@cython.cclass
class Prime:
    @cython.ccall
    def test(self, n: GMPInteger, state: GMPState, reps: cython.int, test: PrimalityTest):
        return bool(primality_test(n.value, state.state, reps, test.value))

    @cython.ccall
    def gen_prime_b(self, state: GMPState, bit_size: cython.int, nb_sprimes: cython.int, reps: cython.int, test: PrimalityTest) -> str:
        n = GMPInteger()
        gen_prime_b(n.value, state.state, bit_size, nb_sprimes, reps, test.value)
        return n.get_value(10)

    @cython.ccall
    def gen_prime_m(self, state: GMPState, m: GMPInteger, nb_sprimes: cython.int, reps: cython.int, test: PrimalityTest) -> str:
        n = GMPInteger()
        gen_prime_m(n.value, state.state, m.value, nb_sprimes, reps, test.value)
        return n.get_value(10)