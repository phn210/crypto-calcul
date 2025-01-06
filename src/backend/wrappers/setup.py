from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

SRC_DIR = "src/backend"
BUILD_DIR = "build/"
WRAPPER_DIR = "src/backend/wrappers"

class CustomBuildExtension(build_ext):
    def run(self):
        self.build_lib = BUILD_DIR
        self.inplace = False
        super().run()

def get_extension(name, c_sources, wrapper_sources=[]):
    module = name.split(".")[-1]
    sources = [f'{SRC_DIR}/{file}' for file in c_sources] + [f'{WRAPPER_DIR}/{module}/__init__.py' if module == "enums" else f'{WRAPPER_DIR}/{module}/__init__.pyx']
    # + [f'{WRAPPER_DIR}/{file}' for file in wrapper_sources]

    include_dirs = [SRC_DIR, f'{SRC_DIR}/include'] + list(
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

# Cython setup
setup(
    name="wrappers",
    ext_modules=cythonize(
        [
            get_extension(
                "wrappers.enums",
                c_sources=[],
            ),
            get_extension(
                "wrappers.gmp",
                c_sources=[],
            ),
            get_extension(
                "wrappers.prime",
                c_sources=["misc/prime/prime_test.c", "misc/prime/prime_gen.c", "rng/rng.c"],
            ),
            get_extension(
                "wrappers.rng",
                c_sources=["rng/rng.c"],
            ),
            get_extension(
                "wrappers.md5",
                c_sources=["hash/md5.c"],
            ),
            get_extension(
                "wrappers.sha1",
                c_sources=["hash/sha1.c"],
            ),
            get_extension(
                "wrappers.sha2",
                c_sources=["hash/sha2.c"],
            ),
            get_extension(
                "wrappers.sha3",
                c_sources=["hash/sha3.c"],
            ),
            get_extension(
                "wrappers.ec",
                c_sources=["ec/ec.c", "hash/sha2.c", "misc/conversion.c"],
            ),
            get_extension(
                "wrappers.mac",
                c_sources=["mac/hmac.c", "hash/md5.c", "hash/sha1.c", "hash/sha2.c", "hash/sha3.c"],
            ),
            get_extension(
                "wrappers.des",
                c_sources=["ske/des.c"],
            )
        ],
        compiler_directives=cython_directives
    ),
    cmdclass={'build_ext': CustomBuildExtension},
    zip_safe=False,
)