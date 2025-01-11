# crypto-calcul

## Overview

`crypto-calcul` is a cryptographic library that provides various functionalities in C with a GUI.

## Prerequisites

- C compiler
- `GMP` library
- Python3
- Cython

## Building the Library

To build the library, follow these steps:

1. Clone the repository.

2. Ensure you have a C compiler and `GMP` library installed.

3. Single-command setup:
   ```sh
   make
   ```
   This will compile all the C source files, create the executables for testing, and wrap C library into Python library.

   If you want to build the library step-by-step, follow the next instructions.

   **Note.** This command runs in parallel by default, you might want to adjust the NUM_CORES variable to match your system.

3. Build the C library:

   ```sh
   # Basic
   make all

   # Parallel
   make build_fast
   ```

4. Setup Python virtual environment and install dependencies:
   ```sh
   python3 -m venv .venv

   if [ -z "$PYTHONPATH" ]; then echo "export PYTHONPATH=$(pwd)/build" >> .venv/bin/activate; fi

   source .venv/bin/activate

   pip install -r requirements.txt
   ```

5. Wrap C modules into Python modules with Cython:

   ```sh
   # Basic
   make wrap

   # Parallel
   make wrap_fast
   ```

## Running Tests

To run the tests, follow these steps:

1. Ensure you have built the libraries as described above.

2. Run the tests for C library:

   ```sh
   # Run all tests
   make test

   # Run tests of a module
   make test_<module_name>
   ```

3. Test Python library for UI:
   ```sh
   python3 src/frontend/test.py
   ```

## Cleaning Up

To clean up the build artifacts, run:

```sh
make clean
```
