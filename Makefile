# Directories
SRC_DIR = src/backend
OBJ_DIR = obj
BIN_DIR = build

# Compiler and flags
CC = clang
CFLAGS = -I$(SRC_DIR) \
		-I$(SRC_DIR)/hash \
		-I$(SRC_DIR)/mac \
 		-I$(SRC_DIR)/misc \
 		-I$(SRC_DIR)/misc/prime \
		-I$(SRC_DIR)/pke \
		-I$(SRC_DIR)/rng \
		-I$(SRC_DIR)/sign \
		-I$(SRC_DIR)/ske
LDFLAGS = -lgmp

# Parameters
SECURITY_LEVEL ?= PARAM_L1

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/**/*.c) $(wildcard $(SRC_DIR)/**/**/*.c)
TEST_SRCS = $(filter %.test.c, $(SRCS))
NON_TEST_SRCS = $(filter-out %.test.c, $(SRCS))
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_OBJS = $(TEST_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
NON_TEST_OBJS = $(NON_TEST_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_EXECS = $(TEST_SRCS:$(SRC_DIR)/%.c=$(BIN_DIR)/%)

# Default target
all: $(TEST_EXECS)

# Create executables for test files
$(BIN_DIR)/%: $(OBJ_DIR)/%.o $(NON_TEST_OBJS) | $(BIN_DIR)
	@mkdir -p $(dir $@)
	$(CC) -D$(SECURITY_LEVEL) -o $@ $^ $(LDFLAGS)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories if they don't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean up build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

info:
	$(info $(SRCS))
	$(info $(OBJS))
	$(info $(TEST_SRCS))
	$(info $(TEST_OBJS))
	$(info $(NON_TEST_SRCS))
	$(info $(NON_TEST_OBJS))

test: $(TEST_EXECS)
	@for exec in $(TEST_EXECS); do \
		$$exec; \
	done

.PHONY: all clean test