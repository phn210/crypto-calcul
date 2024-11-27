from setuptools import setup, Extension
from Cython.Build import cythonize

SRC_DIR = "src/backend"
WRAPPER_DIR = "src/backend/wrappers"

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
            "gmp_wrapper",
            c_sources=[],
            wrapper_sources=["gmp_wrapper.pyx"],
        ),
        get_extension(
            "rng_wrapper",
            c_sources=["rng/rng.c"],
            wrapper_sources=["rng_wrapper.pyx"],
        ),
    ]),
    zip_safe=False,
)