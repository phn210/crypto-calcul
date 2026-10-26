"""Shared plumbing: status checking, byte buffers and output size negotiation."""
from typing import Callable, Tuple

from ._native import ffi, lib

# Covers every fixed-size output (the largest is a 15360-bit RSA value); larger outputs are retried
_DEFAULT_CAPACITY = 2048


class CryptoError(Exception):
    """An error reported by the C library; `status` is its cc_status_t code."""

    def __init__(self, status: int, message: str = None):
        super().__init__(message or ffi.string(lib.cc_strerror(status)).decode())
        self.status = status


def check(status: int) -> None:
    if status != lib.CC_OK:
        raise CryptoError(status)


def check_verify(status: int) -> bool:
    """For verification functions: True if valid, False if not, raises on other errors."""
    if status == lib.CC_ERR_VERIFY:
        return False
    check(status)
    return True


def data(buf) -> "ffi.CData":
    """Read-only C view of a bytes-like object."""
    return ffi.from_buffer("uint8_t[]", buf)


def call_out(func: Callable, *args, capacity: int = _DEFAULT_CAPACITY) -> bytes:
    """Calls func(*args, out, &out_len), growing the buffer once if the library asks for more."""
    for _ in range(2):
        out = ffi.new("uint8_t[]", max(capacity, 1))
        out_len = ffi.new("size_t *", capacity)
        status = func(*args, out, out_len)
        if status != lib.CC_ERR_BUFFER_TOO_SMALL:
            break
        capacity = out_len[0]
    check(status)
    return bytes(ffi.buffer(out, out_len[0]))


def call_out2(func: Callable, *args, capacity: int = _DEFAULT_CAPACITY) -> Tuple[bytes, bytes]:
    """Same as call_out for functions producing two outputs (a, &a_len, b, &b_len)."""
    capacities = [capacity, capacity]
    for _ in range(2):
        a, b = (ffi.new("uint8_t[]", max(c, 1)) for c in capacities)
        a_len, b_len = (ffi.new("size_t *", c) for c in capacities)
        status = func(*args, a, a_len, b, b_len)
        if status != lib.CC_ERR_BUFFER_TOO_SMALL:
            break
        capacities = [a_len[0], b_len[0]]
    check(status)
    return bytes(ffi.buffer(a, a_len[0])), bytes(ffi.buffer(b, b_len[0]))


def to_bytes(n: int) -> bytes:
    """Minimal big-endian encoding of a non-negative integer."""
    if n < 0:
        raise ValueError("negative integers are not supported")
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def fit(key: bytes, size: int) -> bytes:
    """Truncates or zero-pads key material to exactly size bytes."""
    return key[:size].ljust(size, b"\0")
