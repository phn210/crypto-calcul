# Update number of cores to match your system
NUM_CORES = 10
SRC_DIR = src/backend

all test prepare:
	@cd src/backend && time make $@

build_fast:
	@cd src/backend && time make all -j $(NUM_CORES)

test_%: prepare
	@cd $(SRC_DIR)/$* && make test

clean: clean_wrapper
	@cd src/backend && make $@

clean_make:
	rm -rf $(SRC_DIR)/*/Makefile

clean_wrapper:
	rm -rf ./**/*cpython-*
	find . -type f -path "*/wrappers/*.c*" -exec rm {} \;

wrap:
	time python3 src/backend/wrappers/setup.py build_ext

wrap_fast:
	time python3 src/backend/wrappers/setup.py build_ext -j $(NUM_CORES)

.PHONY : all test test_% clean build_fast prepare clean_make wrap wrap_fast clean_wrapper