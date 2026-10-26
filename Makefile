# Thin aliases over CMake + Ninja. The build itself is defined in CMakeLists.txt.
#
# Options (pass on the command line, e.g. `make test SANITIZE=ON`):
#   BUILD_TYPE  Release | Debug | RelWithDebInfo   (default: Release)
#   SANITIZE    ON | OFF                           (default: OFF)
#   SANITIZER   address | leak | thread | undefined (default: address)
#   PYTHON_PKG  ON | OFF, build the Python package (default: ON)

BUILD_DIR  ?= build
BUILD_TYPE ?= Release
SANITIZE   ?= OFF
SANITIZER  ?= address
PYTHON_PKG ?= ON
PYTHON     ?= $(or $(wildcard .venv/bin/python3),$(wildcard .venv/Scripts/python.exe),python3)

MAKEFLAGS += --no-print-directory

all: configure
	@cmake --build $(BUILD_DIR)

# Re-running configure is cheap and keeps the options above in sync with the cache
configure:
	@cmake -S . -B $(BUILD_DIR) -G Ninja --log-level=WARNING \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCC_SANITIZE=$(SANITIZE) \
		-DCC_SANITIZER=$(SANITIZER) \
		-DCC_BUILD_PYTHON=$(PYTHON_PKG) \
		-DPython3_EXECUTABLE=$(abspath $(PYTHON))

test: configure
	@cmake --build $(BUILD_DIR) --target tests
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

# Build and run only one module's tests and their dependencies, e.g. `make test_rsa`
test_%: configure
	@cmake --build $(BUILD_DIR) --target tests_$*
	@ctest --test-dir $(BUILD_DIR) --output-on-failure -L '^$*$$'

# Python package `cryptocalc`, assembled in $(BUILD_DIR)/python
python: configure
	@cmake --build $(BUILD_DIR) --target python

gui: python
	@PYTHONPATH=$(BUILD_DIR)/python $(PYTHON) src/frontend/main.py

gui_%: python
	@PYTHONPATH=$(BUILD_DIR)/python $(PYTHON) src/frontend/$*.py

setup:
	./setup.sh

clean:
	@if [ -f $(BUILD_DIR)/build.ninja ]; then cmake --build $(BUILD_DIR) --target clean; fi

distclean:
	@cmake -E rm -rf $(BUILD_DIR)

.PHONY: all configure test test_% python gui gui_% setup clean distclean
