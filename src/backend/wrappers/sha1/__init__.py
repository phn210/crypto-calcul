import cython

@cython.cclass
class SHA1:
    def hash(self, m: bytes):
        md = cython.cast(cython.p_char, malloc(_SHA1_DIGEST_SIZE))
        buf_m = cython.declare(cython.p_char, m)
        sha1(buf_m, len(m), md, _SHA1_DIGEST_SIZE)
        result = cython.declare(bytes, md[:_SHA1_DIGEST_SIZE])
        free(md)
        return result