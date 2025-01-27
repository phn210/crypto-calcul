import cython

@cython.cclass
class MD5:
    def hash(self, m: bytes):
        md = cython.cast(cython.p_char, malloc(_MD5_DIGEST_SIZE))
        buf_m = cython.declare(cython.p_char, m)
        md5(buf_m, len(m), md, _MD5_DIGEST_SIZE)
        result = cython.declare(bytes, md[:_MD5_DIGEST_SIZE])
        free(md)
        return result