# SymFit Plugin Prototype Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -I./include
LDFLAGS =

# QuickJS integration (optional for prototype)
# If QuickJS is available, compile with it
QUICKJS_DIR = ../external/quickjs
QUICKJS_LIB = $(QUICKJS_DIR)/libquickjs.a

# Check if QuickJS exists
ifeq ($(wildcard $(QUICKJS_LIB)),)
    $(info QuickJS not found - compiling with shim)
    HAVE_QUICKJS = 0
else
    $(info QuickJS found - compiling with full support)
    HAVE_QUICKJS = 1
    CFLAGS += -DHAVE_QUICKJS -I$(QUICKJS_DIR)
    LDFLAGS += $(QUICKJS_LIB) -lm -ldl -lpthread
endif

# Source files
SRC = src/symfit_plugin.c
TEST_SRC = test/test_plugin.c
OBJ = $(SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

# Targets
TARGET = test/test_plugin
LIB = libsymfit_plugin.a

.PHONY: all clean test quickjs help

all: $(TARGET)

# Build QuickJS if needed
quickjs:
	@if [ ! -f "$(QUICKJS_LIB)" ]; then \
		echo "Building QuickJS..."; \
		mkdir -p ../external; \
		cd ../external && \
		git clone https://github.com/bellard/quickjs.git quickjs && \
		cd quickjs && make; \
	else \
		echo "QuickJS already built"; \
	fi

# Build library
$(LIB): $(OBJ)
	ar rcs $@ $^
	@echo "Library built: $(LIB)"

# Build test program
$(TARGET): $(TEST_OBJ) $(LIB)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Test program built: $(TARGET)"

# Compile objects
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run test
test: $(TARGET)
	@echo ""
	@echo "=== Running without plugin ==="
	./$(TARGET)
	@echo ""
	@echo "=== Running with plugin ==="
	./$(TARGET) --plugin examples/simple_plugin.js --moves "ddssd"

# Clean
clean:
	rm -f $(OBJ) $(TEST_OBJ) $(LIB) $(TARGET)
	@echo "Cleaned build artifacts"

# Help
help:
	@echo "SymFit Plugin Prototype"
	@echo ""
	@echo "Targets:"
	@echo "  make              - Build test program"
	@echo "  make quickjs      - Download and build QuickJS"
	@echo "  make test         - Run test program"
	@echo "  make clean        - Clean build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  ./test/test_plugin --plugin examples/simple_plugin.js"
