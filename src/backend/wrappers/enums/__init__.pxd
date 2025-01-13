cdef extern from "common.h":
    ctypedef enum sec_level_t:
        _L0 "L0"
        _L1 "L1"
        _L2 "L2"
        _L3 "L3"

    ctypedef enum hash_func_t:
        _MD5 "MD5"
        _SHA1 "SHA1"
        _SHA2 "SHA2"
        _SHA3 "SHA3"