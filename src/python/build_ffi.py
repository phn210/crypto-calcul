"""Generates the C source of the cryptocalc._native extension from the public header.

The cffi declarations come straight from cryptocalc.h, so the bindings cannot drift from the
C API: preprocessor lines, the C++ guard and comments are stripped, the rest is given to cffi.

Usage: python build_ffi.py <cryptocalc.h> <output.c>
"""
import re
import sys

from cffi import FFI


def cdef_from_header(text: str) -> str:
    text = re.sub(r"#ifdef __cplusplus.*?#endif", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines).replace("CC_API ", "")


def main(header_path: str, output_path: str) -> None:
    with open(header_path, encoding="utf-8") as f:
        cdef = cdef_from_header(f.read())

    ffi = FFI()
    ffi.cdef(cdef)
    ffi.set_source("cryptocalc._native", '#include "cryptocalc.h"')
    ffi.emit_c_code(output_path)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
