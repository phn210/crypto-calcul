-include .env

# Update number of cores to match your system
SRC_DIR = src/backend
MAKEFLAGS += --no-print-directory

all test prepare:
	@cd src/backend && make $@

setup:
	./setup.sh

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

gui: wrap
	@python3 src/frontend/main.py

gui_%:
	@python3 src/frontend/$*.py

.PHONY : all test test_% clean build_fast prepare clean_make wrap clean_wrapper setup gui gui_%