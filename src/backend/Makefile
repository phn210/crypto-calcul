# List all subdirectories dynamically
SUBDIRS := $(shell find . -mindepth 1 -maxdepth 1 -type d)
SUBDIRS_NAME := $(SUBDIRS:./%=%)
EXCLUDE_DIRS := wrappers include ss
INCLUDE_DIRS := $(filter-out $(EXCLUDE_DIRS), $(SUBDIRS_NAME))
MAKE_FILES := $(INCLUDE_DIRS:%=%/Makefile)

%/Makefile.env:
	@if [ ! -f $@ ]; then \
		echo "TEST_DEPS = " > $@; \
	fi \

%/Makefile: %/Makefile.env template
	@cd $* && \
	cp Makefile.env Makefile; \
	cat ../template >> Makefile && \
	cd ..

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