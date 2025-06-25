CC = gcc
CFLAGS = -Wall -Wextra -g
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
UTILS_DIR = Utils

# Listado de fuentes
SRCS = $(wildcard $(SRC_DIR)/*.c)
UTILS = $(wildcard src/$(UTILS_DIR)/*.c)

# Objetos correspondientes
SRCS_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
UTILS_OBJS = $(patsubst $(UTILS_DIR)/%.c, $(OBJ_DIR)/%.o, $(UTILS))
OBJS = $(SRCS_OBJS) $(UTILS_OBJS)

# Ejecutable final
TARGET = $(BIN_DIR)/programa

# Targets principales
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Regla para compilar .c de src
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Regla para compilar .c de Utils
$(OBJ_DIR)/%.o: $(UTILS_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Crear directorios si no existen
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Limpieza
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
