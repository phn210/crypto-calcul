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

def get_extension(name, c_sources, wrapper_sources):
    sources = [f'{SRC_DIR}/{file}' for file in c_sources] + [f'{WRAPPER_DIR}/{file}' for file in wrapper_sources]
    include_dirs = [SRC_DIR, f'{SRC_DIR}/include'] + list(
        set([ f'{SRC_DIR}/{"/".join(file.split("/")[:-1])}' for file in c_sources ])
    )
    return Extension(
        name,
        sources=sources,
        include_dirs=include_dirs,
        libraries=["gmp"],
    )

# Cython setup
setup(
    name="wrappers",
    ext_modules=cythonize([
        get_extension(
            "wrappers.enum",
            c_sources=[],
            wrapper_sources=["enum.pyx"],
        ),
        get_extension(
            "wrappers.gmp",
            c_sources=[],
            wrapper_sources=["gmp.pyx"],
        ),
        get_extension(
            "wrappers.rng",
            c_sources=["rng/rng.c"],
            wrapper_sources=["rng.pyx"],
        ),
        get_extension(
            "wrappers.sha3",
            c_sources=["hash/sha_3.c"],
            wrapper_sources=["sha3.pyx"],
        ),
    ]),
    cmdclass={'build_ext': CustomBuildExtension},
    zip_safe=False,
)