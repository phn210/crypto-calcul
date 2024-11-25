# crypto-calcul

## Overview

`crypto-calcul` is a cryptographic library that provides various functionalities in C with a GUI.

## Prerequisites

- C compiler
- `GMP` library
- Python3

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

5. Run Cython setup script to wrap C libraries into Python modules:

   ```
   python3 src/backend/test.py
   ```

## Running Tests

To run the tests, follow these steps:

1. Ensure you have built the library as described above.

2. Run the tests:
   ```
   make test
   ```

This will execute all the test executables and display the results.

## Cleaning Up

To clean up the build artifacts, run:

```sh
make clean
```
