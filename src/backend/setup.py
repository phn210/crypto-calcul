from setuptools import setup, Extension
from Cython.Build import cythonize

# Cython setup
setup(
    name="wrappers",
    ext_modules=cythonize([
        Extension(
            "gmp_wrapper",
            sources=["src/backend/gmp_wrapper.pyx"],
            libraries=["gmp"],
            include_dirs=["src/backend"],
        ),
        Extension(
            "rng_wrapper",
            sources=[
                "src/backend/rng/rng_wrapper.pyx",
                "src/backend/rng/rng.c",
            ],
            libraries=["gmp"],
            include_dirs=["src/backend", "src/backend/rng"],
            depends=["src/backend/gmp_wrapper.pyx"]
        ),
    ]),
    zip_safe=False,
)