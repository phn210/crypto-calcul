# crypto-calcul

## Overview

`crypto-calcul` is a cryptographic library that provides various functionalities in C with a GUI.

## Prerequisites

- C compiler, e.g. `gcc` or `clang`
- [`CMake`](https://cmake.org/) ≥ 3.20 and [`Ninja`](https://ninja-build.org/)
- [`GMP`](https://gmplib.org/)
- `python3`
- `cython`
- `PyQt`

```sh
# macOS
brew install cmake ninja gmp

# Debian/Ubuntu
sudo apt install cmake ninja-build libgmp-dev
```

### Windows

It's recommended to install the toolchain with [`MSYS2`](https://www.msys2.org/) and run every command below in the MSYS2 MinGW64 terminal.

```sh
pacman -S make \
         mingw-w64-x86_64-gcc \
         mingw-w64-x86_64-cmake \
         mingw-w64-x86_64-ninja \
         mingw-w64-x86_64-gmp \
         mingw-w64-x86_64-python \
         mingw-w64-x86_64-python-pip
```

## Building

The build is defined with CMake ([CMakeLists.txt](CMakeLists.txt), [src/backend/CMakeLists.txt](src/backend/CMakeLists.txt)) and runs on Ninja, which builds in parallel and only rebuilds what changed (including after header edits). The `Makefile` provides short aliases for it.

### Single command

```sh
make setup
```

This creates the Python virtual environment in `.venv`, installs the dependencies, compiles the C library and the tests, and wraps the C library into Python modules.

### Step by step

1. Set up the Python virtual environment and install the dependencies:

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate   # Windows (MSYS2): source .venv/bin/activate or .venv/Scripts/activate
   pip install -r requirements.txt
   ```

2. Build everything (C library, test executables, Python wrappers):

   ```sh
   make
   ```

   Or build only the Python wrappers with `make wrap`.

Outputs go to `build/`: test executables in `build/tests/<module>/`, Python wrappers in `build/wrappers/`.

### Build options

| Option      | Values                                  | Default   |
|-------------|-----------------------------------------|-----------|
| `BUILD_TYPE`| `Release`, `Debug`, `RelWithDebInfo`    | `Release` |
| `SANITIZE`  | `ON`, `OFF`                             | `OFF`     |
| `SANITIZER` | `address`, `leak`, `thread`, `undefined`| `address` |
| `WRAPPERS`  | `ON`, `OFF` (skip the Cython wrappers)  | `ON`      |

```sh
make test SANITIZE=ON SANITIZER=undefined
```

### Building a single target

Each module is a static library that declares only its direct dependencies, so building a target builds exactly what it needs:

```sh
cmake --build build --target rsa             # librsa.a and its dependencies
cmake --build build --target test_rsa_enc    # one test executable
cmake --build build --target wrapper_rsa     # one Python wrapper
```

### Adding a module

Create `src/backend/<module>/` with its sources and `*.test.c` files, then add one line to [src/backend/CMakeLists.txt](src/backend/CMakeLists.txt):

```cmake
cc_module(<module> DEPS <direct dependencies>)
```

For a Python wrapper, add `src/backend/wrappers/<module>/__init__.{py,pxd}` and a `cc_wrapper(<module> <module>)` line to [src/backend/wrappers/CMakeLists.txt](src/backend/wrappers/CMakeLists.txt).

## Running Tests

1. Run the tests of the C library:

   ```sh
   # All tests
   make test

   # Tests of one module (builds only that module and its dependencies)
   make test_<module_name>
   ```

   Tests are registered with CTest, so `ctest --test-dir build -j8` and `ctest --test-dir build -R rsa` also work.

2. Test the Python library used by the UI:

   ```sh
   make wrap
   python3 src/frontend/test.py
   ```

## Graphical User Interface (GUI)

```sh
make gui
```

or

```sh
make gui_<page_name>
```

## Cleaning Up

```sh
make clean       # remove build outputs
make distclean   # remove the whole build directory, including the CMake cache
```
