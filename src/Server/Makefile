CC = gcc
CFLAGS = -Wall -Wextra -g

SRC_DIR = .
OBJ_DIR = ../../obj/server
BIN_DIR = ../../bin/server

# Excluir archivos de test del build principal
SRCS := $(shell find $(SRC_DIR) -name '*.c' ! -path '$(SRC_DIR)/Tests/*')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/programa

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lanl

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $@

# Compilar tests solo si se invoca make tests
test_srcs := $(shell find $(SRC_DIR)/Tests -name '*.c')
test_objs := $(patsubst $(SRC_DIR)/Tests/%.c, $(OBJ_DIR)/Tests/%.o, $(test_srcs))

tests: $(test_objs)
	@echo "Tests compilados. Ejecuta manualmente los binarios de test si lo deseas."

$(OBJ_DIR)/Tests/%.o: $(SRC_DIR)/Tests/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean tests
