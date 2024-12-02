from wrappers.gmp cimport *

cdef extern from "rng.h":
    void rng_init(gmp_randstate_t state)
    void rng_init_with_seed(gmp_randstate_t state, unsigned int seed)
    void rand_int_b(mpz_t result, gmp_randstate_t state, unsigned long bits)
    void rand_int_m(mpz_t result, gmp_randstate_t state, mpz_t n)
    void rand_bytes(char *buf, gmp_randstate_t state, unsigned int byte_len)

cdef class GMPState:
    cdef gmp_randstate_t state

    def __cinit__(self):
        rng_init(self.state)

    def seed(self, unsigned int seed):
        """Seed the random state."""
        rng_init_with_seed(self.state, seed)

cdef class RNG:
    cdef GMPState state

    def __cinit__(self, seed=None):
        self.state = GMPState()
        if seed is not None:
            self.state.seed(seed)

    def rand_int_b(self, unsigned long bits, int base):
        result = GMPInteger()
        rand_int_b(result.value, self.state.state, bits)
        return result.get_value(base)[2:-1]

    def rand_int_m(self, GMPInteger result, GMPInteger modulo, int base):
        result = GMPInteger()
        rand_int_m(result.value, self.state.state, modulo.value)
        return result.get_value(base)[2:-1]

    def rand_bytes(self, int byte_len):
        cdef char *buf = <char *>malloc(byte_len)
        rand_bytes(buf, self.state.state, byte_len)
        result = bytes(buf[:byte_len])
        free(buf)
        return result