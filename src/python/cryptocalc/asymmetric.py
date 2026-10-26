"""RSA, ElGamal, DSA, Diffie-Hellman and the elliptic-curve schemes.

Keys are generated inside a context with keygen() and exposed as Python integers (scalars)
or ECPoint (encoded points). Signatures and two-part ciphertexts are returned as [a, b].
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Union

from ._core import call_out, call_out2, check, check_verify, data, ffi, lib, to_bytes, to_int
from .primitives import HashFunction, SecurityLevel


def _new(constructor, ctype: str, free, *args):
    ctx = ffi.new(f"{ctype} **")
    check(constructor(ctx, *args))
    return ffi.gc(ctx[0], free)


def _get_int(getter, ctx, param) -> int:
    return to_int(call_out(getter, ctx, param))


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

class RSAVariant(Enum):
    TEXTBOOK = lib.CC_RSA_TEXTBOOK
    PKCS1 = lib.CC_RSA_PKCS1
    SECURE = lib.CC_RSA_OAEP_PSS  # OAEP encryption, PSS signatures


class RSAAlgo(Enum):
    """How private-key operations are computed."""
    STANDARD = 0
    CRT = 1


@dataclass
class RSAPublicKey:
    n: int
    e: int


@dataclass
class RSAPrivateKey:
    n: int
    p: int
    q: int
    d: int
    dp: int
    dq: int
    q_inv: int


class RSA:
    def __init__(self, sec_level: SecurityLevel, variant: RSAVariant):
        self.variant = variant
        self._ctx = _new(lib.cc_rsa_new, "cc_rsa_t", lib.cc_rsa_free, sec_level.value, variant.value)

    def keygen(self) -> None:
        check(lib.cc_rsa_keygen(self._ctx))

    @property
    def pubKey(self) -> RSAPublicKey:
        return RSAPublicKey(*(_get_int(lib.cc_rsa_get, self._ctx, p) for p in (lib.CC_RSA_N, lib.CC_RSA_E)))

    @property
    def prvKey(self) -> RSAPrivateKey:
        params = (lib.CC_RSA_N, lib.CC_RSA_P, lib.CC_RSA_Q, lib.CC_RSA_D, lib.CC_RSA_DP, lib.CC_RSA_DQ, lib.CC_RSA_QINV)
        return RSAPrivateKey(*(_get_int(lib.cc_rsa_get, self._ctx, p) for p in params))

    def _use(self, algo: RSAAlgo) -> None:
        check(lib.cc_rsa_use_crt(self._ctx, algo == RSAAlgo.CRT))

    def encrypt(self, message: bytes) -> bytes:
        return call_out(lib.cc_rsa_encrypt, self._ctx, data(message), len(message))

    def decrypt(self, ciphertext: bytes, algo: RSAAlgo = RSAAlgo.CRT) -> bytes:
        self._use(algo)
        return call_out(lib.cc_rsa_decrypt, self._ctx, data(ciphertext), len(ciphertext))

    def sign(self, message: bytes, algo: RSAAlgo = RSAAlgo.CRT) -> bytes:
        self._use(algo)
        return call_out(lib.cc_rsa_sign, self._ctx, data(message), len(message))

    def verify(self, message: bytes, signature: bytes) -> bool:
        return check_verify(lib.cc_rsa_verify(self._ctx, data(message), len(message), data(signature), len(signature)))


# ---------------------------------------------------------------------------
# ElGamal, DSA and Diffie-Hellman (finite fields)
# ---------------------------------------------------------------------------

@dataclass
class DLPublicKey:
    y: int


@dataclass
class DLPrivateKey:
    x: int


class _DiscreteLog:
    def keygen(self) -> None:
        check(self._keygen(self._ctx))

    @property
    def pubKey(self) -> DLPublicKey:
        return DLPublicKey(_get_int(self._get, self._ctx, lib.CC_DL_Y))

    @property
    def prvKey(self) -> DLPrivateKey:
        return DLPrivateKey(_get_int(self._get, self._ctx, lib.CC_DL_X))

    def sign(self, message: bytes) -> List[bytes]:
        return list(call_out2(self._sign, self._ctx, data(message), len(message)))

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        return check_verify(self._verify(self._ctx, data(message), len(message), data(r), len(r), data(s), len(s)))


class ElGamal(_DiscreteLog):
    """ElGamal encryption (message read as an integer below p) and signatures; levels L0 and L1."""

    def __init__(self, sec_level: SecurityLevel):
        self._ctx = _new(lib.cc_elgamal_new, "cc_elgamal_t", lib.cc_elgamal_free, sec_level.value)
        self._get, self._keygen = lib.cc_elgamal_get, lib.cc_elgamal_keygen
        self._sign, self._verify = lib.cc_elgamal_sign, lib.cc_elgamal_verify

    def encrypt(self, message: bytes) -> List[bytes]:
        return list(call_out2(lib.cc_elgamal_encrypt, self._ctx, data(message), len(message)))

    def decrypt(self, c1: bytes, c2: bytes) -> bytes:
        return call_out(lib.cc_elgamal_decrypt, self._ctx, data(c1), len(c1), data(c2), len(c2))


class DSA(_DiscreteLog):
    """DSA with SHA-2 or SHA-3; levels L0 and L1."""

    def __init__(self, sec_level: SecurityLevel, hash_function: HashFunction):
        if hash_function is None:
            raise ValueError("DSA needs a hash function")
        self._ctx = _new(lib.cc_dsa_new, "cc_dsa_t", lib.cc_dsa_free, sec_level.value, hash_function.value)
        self._get, self._keygen = lib.cc_dsa_get, lib.cc_dsa_keygen
        self._sign, self._verify = lib.cc_dsa_sign, lib.cc_dsa_verify


class DiffieHellman:
    """Diffie-Hellman over the ElGamal groups; levels L0 and L1."""

    def __init__(self, sec_level: SecurityLevel):
        self._level = sec_level.value

    def gen_secret(self) -> bytes:
        return call_out(lib.cc_dh_generate_secret, self._level)

    def gen_public(self, secret: bytes) -> bytes:
        return call_out(lib.cc_dh_public, self._level, data(secret), len(secret))

    def compute_shared_secret(self, secret: bytes, peer_public: bytes) -> bytes:
        return call_out(lib.cc_dh_shared_secret, self._level, data(secret), len(secret), data(peer_public), len(peer_public))


# ---------------------------------------------------------------------------
# Elliptic curves
# ---------------------------------------------------------------------------

class Curve(Enum):
    P224 = lib.CC_CURVE_P224
    P256 = lib.CC_CURVE_P256
    P384 = lib.CC_CURVE_P384
    P521 = lib.CC_CURVE_P521
    SECP256K1 = lib.CC_CURVE_SECP256K1
    W25519 = lib.CC_CURVE_W25519
    W448 = lib.CC_CURVE_W448
    CURVE25519 = lib.CC_CURVE_25519
    CURVE448 = lib.CC_CURVE_448
    ED25519 = lib.CC_CURVE_ED25519
    ED448 = lib.CC_CURVE_ED448
    E448 = lib.CC_CURVE_E448


class ECType(Enum):
    WEIERSTRASS = 0
    MONTGOMERY = 1
    EDWARDS = 2


# Curve families, numbered in the order the GUI lists them
class WeierstrassCurve(Enum):
    P224 = 0
    P256 = 1
    P384 = 2
    P521 = 3
    P256K1 = 4
    W25519 = 5
    W448 = 6


class MontgomeryCurve(Enum):
    C25519 = 0
    C448 = 1


class EdwardsCurve(Enum):
    ED25519 = 0
    ED448 = 1
    E448 = 2


_FAMILIES = {
    ECType.WEIERSTRASS: (WeierstrassCurve, [Curve.P224, Curve.P256, Curve.P384, Curve.P521, Curve.SECP256K1, Curve.W25519, Curve.W448]),
    ECType.MONTGOMERY: (MontgomeryCurve, [Curve.CURVE25519, Curve.CURVE448]),
    ECType.EDWARDS: (EdwardsCurve, [Curve.ED25519, Curve.ED448, Curve.E448]),
}


class EC:
    """A curve chosen by family and identifier, e.g. EC(ECType.EDWARDS, EdwardsCurve.ED448)."""

    def __init__(self, curve_type: ECType, curve_id: Enum):
        family, curves = _FAMILIES[curve_type]
        if not isinstance(curve_id, family):
            raise ValueError(f"{curve_id} is not a {curve_type.name.lower()} curve")
        self.curve_type = curve_type
        self.curve_id = curve_id
        self.curve = curves[curve_id.value]


def _curve(curve: Union[EC, Curve]) -> Curve:
    return curve.curve if isinstance(curve, EC) else curve


class ECPoint(bytes):
    """Encoded point: x || y, or x alone on Montgomery curves. Displays as hexadecimal."""

    def __str__(self) -> str:
        return self.hex()


@dataclass
class ECPublicKey:
    point: ECPoint

    # Name used by EC-ElGamal (Y = xG) and ECDSA (Q = dG)
    @property
    def y(self) -> ECPoint:
        return self.point

    @property
    def q(self) -> ECPoint:
        return self.point


@dataclass
class ECPrivateKey:
    scalar: int

    @property
    def x(self) -> int:
        return self.scalar

    @property
    def d(self) -> int:
        return self.scalar


class _ECScheme:
    def keygen(self) -> None:
        check(self._keygen(self._ctx))

    @property
    def pubKey(self) -> ECPublicKey:
        return ECPublicKey(ECPoint(call_out(self._get, self._ctx, lib.CC_EC_PUBLIC)))

    @property
    def prvKey(self) -> ECPrivateKey:
        return ECPrivateKey(_get_int(self._get, self._ctx, lib.CC_EC_PRIVATE))

    def sign(self, message: bytes) -> List[bytes]:
        return list(call_out2(self._sign, self._ctx, data(message), len(message)))

    def verify(self, message: bytes, r: bytes, s: bytes) -> bool:
        return check_verify(self._verify(self._ctx, data(message), len(message), data(r), len(r), data(s), len(s)))


class ECElGamal(_ECScheme):
    """Hashed EC-ElGamal encryption (messages up to the hash size) and EC-ElGamal signatures."""

    def __init__(self, curve: Union[EC, Curve], hash_function: HashFunction = HashFunction.SHA2):
        self._ctx = _new(lib.cc_ecelgamal_new, "cc_ecelgamal_t", lib.cc_ecelgamal_free, _curve(curve).value, hash_function.value)
        self._get, self._keygen = lib.cc_ecelgamal_get, lib.cc_ecelgamal_keygen
        self._sign, self._verify = lib.cc_ecelgamal_sign, lib.cc_ecelgamal_verify

    def encrypt(self, message: bytes) -> List[bytes]:
        return list(call_out2(lib.cc_ecelgamal_encrypt, self._ctx, data(message), len(message)))

    def decrypt(self, c1: bytes, c2: bytes) -> bytes:
        return call_out(lib.cc_ecelgamal_decrypt, self._ctx, data(c1), len(c1), data(c2), len(c2))


class ECDSA(_ECScheme):
    """ECDSA; not available on Montgomery curves."""

    def __init__(self, curve: Union[EC, Curve], hash_function: HashFunction = HashFunction.SHA2):
        self._ctx = _new(lib.cc_ecdsa_new, "cc_ecdsa_t", lib.cc_ecdsa_free, _curve(curve).value, hash_function.value)
        self._get, self._keygen = lib.cc_ecdsa_get, lib.cc_ecdsa_keygen
        self._sign, self._verify = lib.cc_ecdsa_sign, lib.cc_ecdsa_verify


class ECDH:
    def __init__(self, curve: Union[EC, Curve]):
        self._curve = _curve(curve).value

    def gen_secret(self) -> bytes:
        return call_out(lib.cc_ecdh_generate_secret, self._curve)

    def gen_public(self, secret: bytes) -> bytes:
        return call_out(lib.cc_ecdh_public, self._curve, data(secret), len(secret))

    def compute_shared_secret(self, secret: bytes, peer_public: bytes) -> bytes:
        return call_out(lib.cc_ecdh_shared_secret, self._curve, data(secret), len(secret), data(peer_public), len(peer_public))
