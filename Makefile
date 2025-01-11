# Update number of cores to match your system
NUM_CORES = 15
SRC_DIR = src/backend
MAKEFLAGS += --no-print-directory

setup:
	./setup.sh

all test prepare:
	@cd src/backend && make $@

build_fast:
	@cd src/backend && make all -j $(NUM_CORES)

test_%: prepare
	@cd $(SRC_DIR)/$* && make test

clean: clean_wrapper
	@cd src/backend && make $@

clean_make:
	@rm -rf $(SRC_DIR)/*/Makefile

clean_wrapper:
	@rm -rf ./**/*cpython-*
	@rm -rf build/wrappers
	@find . -type f -path "*/wrappers/*.c*" -exec rm {} \;

wrap: all
	@python3 src/backend/wrappers/setup.py build_ext
	@python3 src/backend/wrappers/setup.py clean

wrap_fast: build_fast
	@python3 src/backend/wrappers/setup.py build_ext -j $(NUM_CORES)
	@python3 src/backend/wrappers/setup.py clean

.PHONY : all test test_% clean build_fast prepare clean_make wrap wrap_fast clean_wrapper setup