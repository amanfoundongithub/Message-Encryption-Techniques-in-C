CC       ?= cc
AR       ?= ar
MKDIR_P  ?= mkdir -p

STDFLAGS := -std=c99
WARNFLAGS:= -Wall -Wextra -Wshadow -Wconversion -Wpedantic
INCFLAGS := -Iinclude -Isrc
OPTFLAGS := -O2

# Separate release flags from sanitizer test flags so object files don't collide
CFLAGS   := $(STDFLAGS) $(OPTFLAGS) $(WARNFLAGS) $(INCFLAGS)
SANFLAGS := $(STDFLAGS) -O1 -g $(WARNFLAGS) $(INCFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
SAN_DIR   := $(BUILD_DIR)/san
BIN_DIR   := $(BUILD_DIR)/bin
LIB_NAME  := $(BUILD_DIR)/libscrypt.a

# Add new source files here as your library grows
SRCS := \
	src/cipher/des.c

OBJS     := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
SAN_OBJS := $(patsubst src/%.c,$(SAN_DIR)/%.o,$(SRCS))

TEST_SRCS := \
	tests/test_des.c

TEST_BINS := $(patsubst tests/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

.PHONY: all test clean help

all: $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	@$(MKDIR_P) $(dir $@)
	$(AR) rcs $@ $^

# Normal library objects
$(OBJ_DIR)/%.o: src/%.c
	@$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Sanitized objects for test binaries
$(SAN_DIR)/%.o: src/%.c
	@$(MKDIR_P) $(dir $@)
	$(CC) $(SANFLAGS) -c $< -o $@

# Build and run all test executables with ASan + UBSan
$(BIN_DIR)/%: tests/%.c $(SAN_OBJS)
	@$(MKDIR_P) $(dir $@)
	$(CC) $(SANFLAGS) $< $(SAN_OBJS) -o $@

test: $(TEST_BINS)
	@for bin in $(TEST_BINS); do \
		echo "Running $$bin..."; \
		"$$bin" || exit 1; \
	done

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Targets:"
	@echo "  all    Build static library $(LIB_NAME)"
	@echo "  test   Build and run tests with ASan and UBSan"
	@echo "  clean  Remove $(BUILD_DIR)"