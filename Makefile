CC          ?= cc
AR          ?= ar
CFLAGS      ?= -std=c99 -O2 -Wall -Wextra -Wshadow -Wconversion -Wpedantic -Iinclude -Isrc
SAN_FLAGS   := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

BUILD_DIR   := build
LIB_TARGET  := $(BUILD_DIR)/libscrypt.a

# Source files for the static library
SRCS        := src/cipher/des.c src/cipher/aes.c src/hash/sha256.c \
               src/cipher/chacha20.c src/mac/poly1305.c src/aead/chacha20_poly1305.c
OBJS        := $(patsubst src/%.c,$(BUILD_DIR)/obj/%.o,$(SRCS))

# Test sources and test binaries in build/bin/
TEST_SRCS   := tests/test_des.c tests/test_aes.c tests/test_sha256.c \
               tests/test_chacha20.c tests/test_chacha20_poly1305.c
TEST_BINS   := $(patsubst tests/%.c,$(BUILD_DIR)/bin/%,$(TEST_SRCS))

.PHONY: all test test-san clean

all: $(LIB_TARGET)

# Compile library object files into build/obj/
$(BUILD_DIR)/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Archive into static library
$(LIB_TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

# Build test binaries linked against libscrypt.a
$(BUILD_DIR)/bin/test_%: tests/test_%.c $(LIB_TARGET)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB_TARGET) -o $@

# Run all test binaries
test: $(TEST_BINS)
	@for bin in $(TEST_BINS); do \
		echo "Running $$bin..."; \
		"$$bin" || exit 1; \
	done

# Sanitizer build
test-san:
	@mkdir -p $(BUILD_DIR)/san/bin
	$(CC) $(CFLAGS) $(SAN_FLAGS) $(SRCS) tests/test_des.c -o $(BUILD_DIR)/san/bin/test_des
	$(CC) $(CFLAGS) $(SAN_FLAGS) $(SRCS) tests/test_aes.c -o $(BUILD_DIR)/san/bin/test_aes
	$(CC) $(CFLAGS) $(SAN_FLAGS) $(SRCS) tests/test_sha256.c -o $(BUILD_DIR)/san/bin/test_sha256
	@echo "Running sanitizer tests..."
	./$(BUILD_DIR)/san/bin/test_des
	./$(BUILD_DIR)/san/bin/test_aes
	./$(BUILD_DIR)/san/bin/test_sha256

clean:
	rm -rf $(BUILD_DIR)