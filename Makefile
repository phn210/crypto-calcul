# Directories
SRC_DIR = src/backend
INC_DIR = src/backend/include
WRAP_DIR = src/backend/wrappers
OBJ_DIR = obj
BIN_DIR = build

# Compiler and flags
CC = gcc
CFLAGS = -I$(INC_DIR)
LDFLAGS = -lgmp

# Source files
SRCS = $(filter-out $(WRAP_DIR)/%.c, $(shell find $(SRC_DIR) -name "*.c"))
TEST_SRCS = $(filter %.test.c, $(SRCS))
NON_TEST_SRCS = $(filter-out %.test.c %wrapper.c, $(SRCS))
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_OBJS = $(TEST_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
NON_TEST_OBJS = $(NON_TEST_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_EXECS = $(TEST_SRCS:$(SRC_DIR)/%.c=$(BIN_DIR)/%)

# Default target
all: $(TEST_EXECS)

# Create executables for test files
$(BIN_DIR)/%: $(OBJ_DIR)/%.o $(NON_TEST_OBJS) | $(BIN_DIR)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(shell cat $(SRC_DIR)/$*.txt) $(LDFLAGS)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories if they don't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

wrap: clean_wrapper
	python3 src/backend/wrappers/setup.py build_ext

# Clean up build artifacts
clean: clean_wrapper
	rm -rf $(OBJ_DIR) $(BIN_DIR)

clean_wrapper:
	rm -rf ./**/*cpython-*
	find . -type f -path "*/wrappers/*.c" -exec rm {} \;

info:
	$(info "SRCS:" $(SRCS))
	$(info "OBJS:" $(OBJS))
	$(info "TEST_SRCS:" $(TEST_SRCS))
	$(info "TEST_OBJS:" $(TEST_OBJS))
	$(info "NON_TEST_SRCS:" $(NON_TEST_SRCS))
	$(info "NON_TEST_OBJS:" $(NON_TEST_OBJS))
	$(info "TEST_EXECS:" $(TEST_EXECS))
	$(info "SHARED_LIBS:" $(SHARED_LIBS))

test: $(TEST_EXECS)
	@for exec in $(TEST_EXECS); do \
		$$exec; \
	done

test_rng: $(BIN_DIR)/rng/rng.test
	$(BIN_DIR)/rng/rng.test

test_prime: $(BIN_DIR)/misc/prime/prime.test
	$(BIN_DIR)/misc/prime/prime.test

test_conversion: $(BIN_DIR)/misc/conversion.test
	$(BIN_DIR)/misc/conversion.test

test_rsa: $(BIN_DIR)/pke/rsa.test
	$(BIN_DIR)/pke/rsa.test

test_elgamal: $(BIN_DIR)/pke/elgamal.test
	$(BIN_DIR)/pke/elgamal.test

test_md5: $(BIN_DIR)/hash/md5.test
	$(BIN_DIR)/hash/md5.test

test_sha1: $(BIN_DIR)/hash/sha1.test
	$(BIN_DIR)/hash/sha1.test

test_sha2: $(BIN_DIR)/hash/sha2.test
	$(BIN_DIR)/hash/sha2.test

test_sha3: $(BIN_DIR)/hash/sha3.test
	$(BIN_DIR)/hash/sha3.test

test_dsa: $(BIN_DIR)/sign/dsa.test
	$(BIN_DIR)/sign/dsa.test

test_ecdsa: $(BIN_DIR)/sign/ecdsa.test
	$(BIN_DIR)/sign/ecdsa.test

test_rsa_sig: $(BIN_DIR)/sign/rsa.test
	$(BIN_DIR)/sign/rsa.test

test_elgamal_sig: $(BIN_DIR)/sign/elgamal.test
	$(BIN_DIR)/sign/elgamal.test

test_hmac: $(BIN_DIR)/mac/hmac.test
	$(BIN_DIR)/mac/hmac.test

test_ec: $(BIN_DIR)/ec/ec.test
	$(BIN_DIR)/ec/ec.test

test_des: $(BIN_DIR)/ske/des.test
	$(BIN_DIR)/ske/des.test

test_aes: $(BIN_DIR)/ske/aes.test
	$(BIN_DIR)/ske/aes.test

.PHONY: all clean test

.PRECIOUS: obj/%.o