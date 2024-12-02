cdef class GMPInteger:

    def __cinit__(self):
        mpz_init(self.value)

    def __dealloc__(self):
        mpz_clear(self.value)

    def __str__(self):
        cdef char *str_rep = <char *>malloc(256)
        mpz_get_str(str_rep, 10, self.value)
        result = str(str_rep)
        free(str_rep)
        return result

    cdef set_value(self, str value, int base):
        mpz_set_str(self.value, value.encode('utf-8'), base)

    cdef get_value(self, int base):
        cdef char *str_rep = <char *>malloc(256)
        mpz_get_str(str_rep, base, self.value)
        result = str(str_rep)
        free(str_rep)
        return result