# Runs every test (C, public API and Python) with AddressSanitizer and UndefinedBehaviorSanitizer.
# The sanitizer runtime is located and preloaded into Python by CMake.
make test BUILD_DIR=build-asan SANITIZE=ON SANITIZER=address,undefined
