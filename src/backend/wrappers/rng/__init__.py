import cython
from wrappers.gmp import GMPInteger

@cython.cclass
class GMPState:
    def __init__(self):
        rng_init(self.state)

    def seed(self, seed):
        """Seed the random state."""
        rng_init_with_seed(self.state, seed)


@cython.cclass
class RNG:
    def __init__(self, seed=None):
        self.state = GMPState()
        if seed is not None:
            self.state.seed(seed)
    
    @cython.ccall
    def rand_int_b(self, bits: cython.ulong, base: cython.int) -> str:
        result = GMPInteger()
        rand_int_b(result.value, self.state.state, bits)
        return result.get_value(base)

    @cython.ccall
    def rand_int_m(self, modulo: GMPInteger, base: cython.int) -> str:
        result = GMPInteger()
        rand_int_m(result.value, self.state.state, modulo.value)
        return result.get_value(base)

    @cython.ccall
    def rand_bytes(self, byte_len: cython.int) -> bytes:
        buf = cython.cast(cython.p_char, malloc(byte_len))
        rand_bytes(buf, self.state.state, byte_len)
        result = cython.declare(bytes, buf[:byte_len])
        free(buf)
        return result