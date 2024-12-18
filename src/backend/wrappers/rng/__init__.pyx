cdef class GMPState:

    def __cinit__(self):
        rng_init(self.state)

    cpdef seed(self, unsigned int seed):
        """Seed the random state."""
        rng_init_with_seed(self.state, seed)

cdef class RNG:
    cdef public GMPState state

    def __cinit__(self, seed=None):
        self.state = GMPState()
        if seed is not None:
            self.state.seed(seed)

    def rand_int_b(self, unsigned long bits, int base):
        result = GMPInteger()
        rand_int_b(result.value, self.state.state, bits)
        return result.get_value(base)

    def rand_int_m(self, GMPInteger modulo, int base):
        result = GMPInteger()
        rand_int_m(result.value, self.state.state, modulo.value)
        return result.get_value(base)

    def rand_bytes(self, int byte_len):
        cdef char *buf = <char *>malloc(byte_len)
        rand_bytes(buf, self.state.state, byte_len)
        result = bytes(buf[:byte_len])
        free(buf)
        return result