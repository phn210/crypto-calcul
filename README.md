# crypto-calcul

## Overview

`crypto-calcul` is a cryptographic library that provides various functionalities in C with a GUI.

## Prerequisites

- C compiler, e.g. `gcc` or `clang`
- [`GMP`](https://gmplib.org/)
- `python3`
- `cython`
- `PyQt`

### Windows

It's recommended to install `gcc`, `GMP`, and `python3` with [`MSYS2`](https://www.msys2.org/), and `pwsh` to follow the next steps.

```sh
# Run in MSYS2 terminal
pacman -S mingw-w64-x86_64-gcc \
         mingw-w64-x86_64-gmp \
         mingw-w64-x86_64-python \
         mingw-w64-x86_64-python-pip
```

## Building the Library (Linux/MacOS)

Clone the repository, ensure the prerequisites are installed, and build the library with follow these steps (in the cloned directory):

### For Linux/MacOS

#### Single-command

```sh
make setup
```

This will compile all the C source files, create the executables for testing, and wrap C library into Python library.

If you want to build the library step-by-step, follow the next instructions.

**Note.** This command runs in parallel by default, you might want to adjust the NUM_CORES variable to match your system.

#### Step-by-step

1. Build the C library:

   ```sh
   # Basic
   make all

   # Parallel
   make build_fast
   ```

2. Setup Python virtual environment and install dependencies:
      
   ```sh
   python3 -m venv .venv

   source .venv/bin/activate

   pip install -r requirements.txt
   ```

3. Wrap C modules into Python modules with Cython:

   ```sh
   # Basic
   make wrap

   # Parallel
   make wrap_fast
   ```

### For Windows

1. Build the C library:

   ```sh
   make all -f Makefile.win
   ```

2. Setup Python virtual environment and install dependencies:
      
   ```sh
   python3 -m venv .venv

   .venv\\bin\\activate
   # or .venv\\Scripts\\Activate.ps1

   pip install -r requirements.txt
   ```

3. Wrap C modules into Python modules with Cython:

   ```sh
   # Basic
   make wrap -f Makefile.win

   # Parallel
   make wrap_fast -f Makefile.win
   ```

## Running Tests

To run the tests, follow these steps:

1. Ensure you have built the libraries as described above.

2. Run the tests for C library:

   ```sh
   # Run all tests
   make test # -f Makefile.win

   # Run tests of a module
   make test_<module_name> # -f Makefile.win
   ```

   3. Test Python library for UI:

   ```sh
   python3 src/frontend/test.py
   ```

## Graphical User Interface (GUI)

```
make gui
```

or 

```
make gui_<page_name>
```

## Cleaning Up

To clean up the build artifacts, run:

```sh
make clean # -f Makefile.win
```