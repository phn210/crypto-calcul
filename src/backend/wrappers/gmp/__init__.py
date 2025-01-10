import cython

@cython.cclass
class GMPInteger:
    value: mpz_t
    
    def __init__(self):
        mpz_init(self.value)

    def __del__(self):
        mpz_clear(self.value)

    def __str__(self):
        str_rep = cython.cast(cython.p_char, malloc(mpz_sizeinbase(self.value, 10) + 2))
        mpz_get_str(str_rep, 10, self.value)
        result = cython.cast(bytes, str_rep).decode('utf-8')
        free(str_rep)
        return result

    @cython.ccall
    def set_value(self, value: str, base: cython.int) -> cython.void:
        mpz_set_str(self.value, value.encode('utf-8'), base)

    @cython.ccall
    def get_value(self, base: cython.int) -> str:
        str_rep = cython.cast(cython.p_char, malloc(mpz_sizeinbase(self.value, base) + 2))
        mpz_get_str(str_rep, base, self.value)
        result = cython.cast(bytes, str_rep).decode('utf-8')
        free(str_rep)
        return result