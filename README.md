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

3. Build the library:

   ```sh
   make
   ```

   This will compile all the source files and create the necessary executables for testing.

4. Setup Python virtual environment and install dependencies:

   ```
   python3 -m venv .venv

   if [ -z "$PYTHONPATH" ]; then echo "export PYTHONPATH=./build" >> .venv/bin/activate; fi

   source .venv/bin/activate

   pip install -r requirements.txt
   ```

5. Wrap C libraries into Python modules:

   ```
   make wrap
   ```

## Running Tests

To run the tests, follow these steps:

1. Ensure you have built the library as described above.

2. Run the tests:

   ```
   # Run all tests
   make test

   # Run tests of a module
   make test_<module_name>
   ```

3. Test Cython wrapper for UI:
   ```
   python3 src/frontend/test.py
   ```

## Cleaning Up

To clean up the build artifacts, run:

```sh
make clean
```
