SRC_DIR = src/backend

all test prepare:
	@cd src/backend && make $@

clean: clean_wrapper
	@cd src/backend && make $@

clean_make:
	rm -rf $(SRC_DIR)/*/Makefile

clean_wrapper:
	rm -rf ./**/*cpython-*
	find . -type f -path "*/wrappers/*.c*" -exec rm {} \;

wrap:
	python3 src/backend/wrappers/setup.py build_ext

test_%: prepare
	@cd $(SRC_DIR)/$* && make test

.PHONY : all test test_% clean prepare wrap clean_wrapper