"""Security levels, hash functions, random numbers and primes."""
from enum import Enum

from ._core import call_out, check, data, ffi, lib, to_bytes, to_int


class SecurityLevel(Enum):
    """Security level; the value is the level in bits."""
    L0 = lib.CC_SEC_112
    L1 = lib.CC_SEC_128
    L2 = lib.CC_SEC_192
    L3 = lib.CC_SEC_256


class HashFunction(Enum):
    MD5 = lib.CC_HASH_MD5
    SHA1 = lib.CC_HASH_SHA1
    SHA2 = lib.CC_HASH_SHA2
    SHA3 = lib.CC_HASH_SHA3


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

class Hash:
    """A hash function; for SHA-2 and SHA-3 the security level selects the output size."""

    def __init__(self, hash_function: HashFunction, sec_level: SecurityLevel = SecurityLevel.L1):
        self.hash_function = hash_function
        self.sec_level = sec_level

    def hash(self, message: bytes) -> bytes:
        return call_out(lib.cc_hash, self.hash_function.value, self.sec_level.value, data(message), len(message))


class MD5(Hash):
    def __init__(self):
        super().__init__(HashFunction.MD5)


class SHA1(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA1)


class SHA224(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA2, SecurityLevel.L0)


class SHA256(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA2, SecurityLevel.L1)


class SHA384(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA2, SecurityLevel.L2)


class SHA512(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA2, SecurityLevel.L3)


class SHA3_224(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA3, SecurityLevel.L0)


class SHA3_256(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA3, SecurityLevel.L1)


class SHA3_384(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA3, SecurityLevel.L2)


class SHA3_512(Hash):
    def __init__(self):
        super().__init__(HashFunction.SHA3, SecurityLevel.L3)


class SHAKE:
    """Extendable-output function used incrementally: update() absorbs input, squeeze() reads output.

    Absorbing more input restarts the output stream over everything absorbed so far.
    """

    def __init__(self, security_bits: int):
        self.security_bits = security_bits
        self._absorbed = bytearray()
        self._squeezed = 0

    def update(self, message: bytes) -> None:
        self._absorbed += message
        self._squeezed = 0

    def xof(self) -> None:
        """Ends absorption. Kept for compatibility: squeeze() finalizes on its own."""

    def squeeze(self, length: int) -> bytes:
        end = self._squeezed + length
        out = ffi.new("uint8_t[]", max(end, 1))
        check(lib.cc_shake(self.security_bits, data(self._absorbed), len(self._absorbed), out, end))
        result = bytes(ffi.buffer(out, end))[self._squeezed:]
        self._squeezed = end
        return result


class SHAKE128(SHAKE):
    def __init__(self):
        super().__init__(128)


class SHAKE256(SHAKE):
    def __init__(self):
        super().__init__(256)


# ---------------------------------------------------------------------------
# Random numbers and primes
# ---------------------------------------------------------------------------

class RNG:
    """Random generator, seeded from the system or, for reproducible experiments, from `seed`."""

    def __init__(self, seed: int = None):
        rng = ffi.new("cc_rng_t **")
        if seed is None:
            check(lib.cc_rng_new(rng))
        else:
            check(lib.cc_rng_new_seeded(rng, seed & 0xFFFFFFFF))
        self._rng = ffi.gc(rng[0], lib.cc_rng_free)

    def rand_int_b(self, bits: int) -> int:
        """Uniform integer in [0, 2^bits)."""
        return to_int(call_out(lib.cc_random_bits, self._rng, bits, capacity=bits // 8 + 1))

    def rand_int_m(self, modulo: int) -> int:
        """Uniform integer in [0, modulo)."""
        m = to_bytes(modulo)
        return to_int(call_out(lib.cc_random_below, self._rng, data(m), len(m), capacity=len(m)))

    def rand_bytes(self, length: int) -> bytes:
        out = ffi.new("uint8_t[]", max(length, 1))
        check(lib.cc_random_bytes(self._rng, out, length))
        return bytes(ffi.buffer(out, length))


class PrimalityTest(Enum):
    GMP = lib.CC_PRIME_TEST_GMP
    FERMAT = lib.CC_PRIME_TEST_FERMAT
    MILLER_RABIN = lib.CC_PRIME_TEST_MILLER_RABIN


class Prime:
    """Probabilistic primality testing and prime generation."""

    def test(self, n: int, rounds: int = 25, test: PrimalityTest = PrimalityTest.MILLER_RABIN) -> bool:
        b = to_bytes(n)
        is_prime = ffi.new("int *")
        check(lib.cc_is_prime(data(b), len(b), test.value, rounds, is_prime))
        return bool(is_prime[0])

    def gen_prime_b(self, bits: int, small_primes: int = 100, rounds: int = 25,
                    test: PrimalityTest = PrimalityTest.MILLER_RABIN) -> int:
        """Random prime of `bits` bits."""
        return to_int(call_out(lib.cc_prime_bits, bits, small_primes, test.value, rounds, capacity=bits // 8 + 1))

    def gen_prime_m(self, m: int, small_primes: int = 100, rounds: int = 25,
                    test: PrimalityTest = PrimalityTest.MILLER_RABIN) -> int:
        """Random prime below m."""
        b = to_bytes(m)
        return to_int(call_out(lib.cc_prime_below, data(b), len(b), small_primes, test.value, rounds, capacity=len(b)))
