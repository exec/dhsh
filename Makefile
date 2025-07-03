# Makefile for dhsh - The Dumb, Hardened Shell

# Compiler
CC = gcc

# Target executable name
TARGET = dhsh

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# --- Compiler and Linker Flags ---

# CFLAGS: Flags for the C compiler
# -I$(INC_DIR): Add include directory to search path
# -O2: Good level of optimization
# -Wall -Wextra -Wpedantic: Enable extensive warnings
# -march=native: Optimize for the host CPU architecture (Arch Linux specific)
# -flto \: Enable Link-Time Optimization (Arch Linux default)
#
# Hardening Flags:
# -D_FORTIFY_SOURCE=3: Strongest level of glibc overflow protection
# -fstack-protector-strong: Protect against stack smashing attacks
# -fPIE: Generate Position-Independent Executable code for ASLR
CFLAGS = -I$(INC_DIR) -O2 -Wall -Wextra -Wpedantic -march=native -flto \
         -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE

# LDFLAGS: Flags for the linker
# -lreadline: Link with the readline library
#
# Hardening Flags:
# -pie: Link as a Position-Independent Executable
# -Wl,-z,relro: Mark relocations as read-only after linking
# -Wl,-z,now: Resolve all symbols at load time, not lazily
LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now

# --- Build Targets ---

# Default target: build the executable
all: $(BUILD_DIR)/$(TARGET)

# Link the object files to create the final executable
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile source files into object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install the executable to /usr/local/bin
install: all
	install -Dm755 $(BUILD_DIR)/$(TARGET) /usr/local/bin/$(TARGET)

# Uninstall the executable
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
