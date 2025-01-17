-include ../../.env

# List all subdirectories dynamically
SUBDIRS := $(shell find . -mindepth 1 -maxdepth 1 -type d)
SUBDIRS_NAME := $(SUBDIRS:./%=%)
EXCLUDE_DIRS := wrappers include $(EXCLUDED_MODULES)
INCLUDE_DIRS := $(filter-out $(EXCLUDE_DIRS), $(SUBDIRS_NAME))
MAKE_FILES := $(INCLUDE_DIRS:%=%/Makefile)

%/Makefile: template
	cp template $*/Makefile

prepare: $(MAKE_FILES)

all test: prepare
	@for dir in $(SUBDIRS); do \
		if [ -f $$dir/Makefile ]; then \
			$(MAKE) -C $$dir $@; \
		fi \
	done

clean:
	@for dir in $(SUBDIRS); do \
		if [ -f $$dir/Makefile ]; then \
			$(MAKE) -C $$dir $@; \
		fi \
	done

.PHONY: all test clean prepare