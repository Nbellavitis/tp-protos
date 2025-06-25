CC = gcc
CFLAGS = -Wall -Wextra -g

SRC_DIR = src
NEG_DIR = $(SRC_DIR)/Negotiation
UTILS_DIR = $(SRC_DIR)/Utils
OBJ_DIR = obj
BIN_DIR = bin

# Archivos fuente
SRCS = $(wildcard $(SRC_DIR)/*.c)
UTILS = $(wildcard $(UTILS_DIR)/*.c)
NEG = $(wildcard $(NEG_DIR)/*.c)

# Archivos objeto: obj/Utils/foo.o por ejemplo
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS)) \
       $(patsubst $(UTILS_DIR)/%.c, $(OBJ_DIR)/Utils/%.o, $(UTILS)) \
       $(patsubst $(NEG_DIR)/%.c, $(OBJ_DIR)/Negotiation/%.o, $(NEG))

# Ejecutable
TARGET = $(BIN_DIR)/programa

# Target principal
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Regla genérica para compilar .c en .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/Utils/%.o: $(UTILS_DIR)/%.c | $(OBJ_DIR)/Utils
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/Negotiation/%.o: $(NEG_DIR)/%.c | $(OBJ_DIR)/Negotiation
	$(CC) $(CFLAGS) -c $< -o $@

# Crear directorios
$(BIN_DIR):
	mkdir -p $@

$(OBJ_DIR):
	mkdir -p $@

$(OBJ_DIR)/Utils:
	mkdir -p $@

$(OBJ_DIR)/Negotiation:
	mkdir -p $@

# Limpieza
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean
