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
cdef extern from "cryptocalc.h":
    ctypedef enum cc_status_t:
        CC_OK
        CC_ERR_VERIFY

    const char *cc_strerror(cc_status_t)

# Raises CryptoError when status is not CC_OK
cdef int check(cc_status_t status) except -1
# For verify functions: 1 if CC_OK, 0 if CC_ERR_VERIFY, raises CryptoError otherwise
cdef int check_verify(cc_status_t status) except -1
