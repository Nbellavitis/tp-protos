# ==================================================================
#  Makefile — perfil OPT por defecto; BUILD=debug o BUILD=safe
#  para compilar con sanitizadores y LOG_LEVEL_DEBUG.
# ==================================================================
include ../Makefile.inc
CC ?= gcc

ifeq ($(filter $(BUILD),debug safe),)   # cualquier valor ≠ debug|safe ⇒ OPT
  CFLAGS  := $(CFLAGS_OPT)
  LDFLAGS := $(LDFLAGS_OPT)
else
  CFLAGS  := $(CFLAGS_DEBUG)
  LDFLAGS := $(LDFLAGS_DEBUG)
endif

SRC_DIR := .
OBJ_DIR := ../../obj/server
BIN_DIR := ../../bin/server
TARGET  := $(BIN_DIR)/programa

SRCS := $(shell find $(SRC_DIR) -name '*.c' ! -path '$(SRC_DIR)/Tests/*')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $@

TEST_SRCS := $(shell find $(SRC_DIR)/Tests -name '*.c')
TEST_OBJS := $(patsubst $(SRC_DIR)/Tests/%.c,$(OBJ_DIR)/Tests/%.o,$(TEST_SRCS))

tests: $(TEST_OBJS)

$(OBJ_DIR)/Tests/%.o: $(SRC_DIR)/Tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all tests clean
