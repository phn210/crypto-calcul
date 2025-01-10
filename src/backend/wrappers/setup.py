import os
from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

SRC_DIR = "src/backend"
BUILD_DIR = "build/"
WRAPPER_DIR = "src/backend/wrappers"

os.environ["CC"] = "clang"
class CustomBuildExtension(build_ext):
    def run(self):
        self.build_lib = BUILD_DIR
        self.inplace = False
        super().run()

def get_extension(*args):
    name = args[0]
    c_sources = args[1]
    
    module = name.split(".")[-1]
    sources = [f'{SRC_DIR}/{file}' for file in c_sources] + [f'{WRAPPER_DIR}/{module}/__init__.py']

    include_dirs = [f'{SRC_DIR}/include'] + list(
        set([ f'{SRC_DIR}/{"/".join(file.split("/")[:-1])}' for file in c_sources ])
    )
    
    return Extension(
        name,
        sources=sources,
        include_dirs=include_dirs,
        libraries=["gmp"],
        language="c",
    )

cython_directives = {
    "boundscheck": "False",
    "wraparound": "False",
    "cdivision": "True",
    "language_level": "3",
    "emit_code_comments": "False",
}

enum_ext = get_extension("wrappers.enums", [])
gmp_ext = get_extension("wrappers.gmp", ["misc/conversion.c"])
rng_ext = get_extension("wrappers.rng", ["rng/rng.c"])
prime_ext = get_extension(
    "wrappers.prime", 
    ["prime/prime_test.c", "prime/prime_gen.c", "rng/rng.c"]
)
md5_ext = get_extension("wrappers.md5", ["md5/md5.c"])
sha1_ext = get_extension("wrappers.sha1", ["sha1/sha1.c"])
sha2_ext = get_extension("wrappers.sha2", ["sha2/sha2.c"])
sha3_ext = get_extension("wrappers.sha3", ["sha3/sha3.c"])
ec_ext = get_extension("wrappers.ec", ["ec/ec.c", "sha2/sha2.c", "misc/conversion.c"])
mac_ext = get_extension("wrappers.mac", [
    "mac/hmac.c", "mac/cbc_mac.c", "md5/md5.c", "sha1/sha1.c", \
    "sha2/sha2.c", "sha3/sha3.c", "aes/aes.c", "misc/conversion.c"
])
des_ext = get_extension("wrappers.des", ["des/des.c", "misc/conversion.c"])
aes_ext = get_extension("wrappers.aes", ["aes/aes.c", "misc/conversion.c"])
rsa_ext = get_extension("wrappers.rsa", [
    "rsa/enc.c", "rsa/sig.c", "rng/rng.c", "md5/md5.c", "sha1/sha1.c", "sha2/sha2.c", \
    "sha3/sha3.c", "mgf/mgf.c", "misc/conversion.c", "prime/prime_test.c", "prime/prime_gen.c"
])
elgamal_ext = get_extension("wrappers.elgamal", [
    "elgamal/enc.c", "elgamal/sig.c", "rng/rng.c", "sha2/sha2.c", "misc/conversion.c", \
    "prime/prime_test.c", "prime/prime_gen.c"
])
ecelgamal_ext = get_extension("wrappers.ecelgamal", [
    "ecelgamal/enc.c", "ecelgamal/sig.c", "ec/ec.c", "rng/rng.c", "sha2/sha2.c", \
    "sha3/sha3.c", "misc/conversion.c"
])
dsa_ext = get_extension("wrappers.dsa", [
    "dsa/dsa.c", "rng/rng.c", "misc/conversion.c", "sha2/sha2.c",
    "sha3/sha3.c", "prime/prime_gen.c", "prime/prime_test.c"
])
ecdsa_ext = get_extension("wrappers.ecdsa", [
    "ecdsa/ecdsa.c", "ec/ec.c", "rng/rng.c", "sha2/sha2.c", "sha3/sha3.c","misc/conversion.c"
])
dh_ext = get_extension("wrappers.dh", [
    "dh/dh.c", "elgamal/enc.c", "rng/rng.c", "misc/conversion.c", \
    "prime/prime_gen.c", "prime/prime_test.c"
])
ecdh_ext = get_extension("wrappers.ecdh", [
    "ecdh/ecdh.c", "ecelgamal/enc.c", "ec/ec.c", "rng/rng.c", "sha2/sha2.c", \
    "sha3/sha3.c", "misc/conversion.c"
])


# Cython setup
setup(
    name="wrappers",
    ext_modules=cythonize(
        [
            enum_ext, gmp_ext, rng_ext, prime_ext, ec_ext,
            md5_ext, sha1_ext, sha2_ext, sha3_ext, mac_ext, des_ext, aes_ext,
            rsa_ext, elgamal_ext, ecelgamal_ext, dsa_ext, ecdsa_ext, dh_ext, ecdh_ext
        ],
        compiler_directives=cython_directives,
        depfile=True,
        exclude=[]
    ),
    cmdclass={'build_ext': CustomBuildExtension},
    zip_safe=False,
)