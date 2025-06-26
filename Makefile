CC      = gcc
BASE_CFLAGS = -Wall -Wextra -g
DBG_CFLAGS  = -Og -ggdb3 -fno-omit-frame-pointer -DDEBUG
DBG_LDFLAGS = -rdynamic

SRC_DIR   = src
NEG_DIR   = $(SRC_DIR)/Negotiation
UTILS_DIR = $(SRC_DIR)/Utils
AUTH_DIR  = $(SRC_DIR)/Auth
REQ_DIR   = $(SRC_DIR)/Request

OBJ_DIR = obj
BIN_DIR = bin

SRCS  = $(wildcard $(SRC_DIR)/*.c)
UTILS = $(wildcard $(UTILS_DIR)/*.c)
NEG   = $(wildcard $(NEG_DIR)/*.c)
AUTH  = $(wildcard $(AUTH_DIR)/*.c)
REQ   = $(wildcard $(REQ_DIR)/*.c)

OBJS = $(patsubst $(SRC_DIR)/%.c,        $(OBJ_DIR)/%.o,              $(SRCS)) \
       $(patsubst $(UTILS_DIR)/%.c,      $(OBJ_DIR)/Utils/%.o,        $(UTILS)) \
       $(patsubst $(NEG_DIR)/%.c,        $(OBJ_DIR)/Negotiation/%.o,  $(NEG)) \
       $(patsubst $(AUTH_DIR)/%.c,       $(OBJ_DIR)/Auth/%.o,         $(AUTH)) \
       $(patsubst $(REQ_DIR)/%.c,        $(OBJ_DIR)/Request/%.o,      $(REQ))

TARGET = $(BIN_DIR)/programa

# ---------- default build -------------------------------------------------
all: CFLAGS := $(BASE_CFLAGS)
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

# ---------- debug build ---------------------------------------------------
debug: CFLAGS  := $(BASE_CFLAGS) $(DBG_CFLAGS)
debug: LDFLAGS := $(DBG_LDFLAGS)
debug: clean $(TARGET)

# ---------- quick gdb launcher --------------------------------------------
gdb: all
	gdb $(TARGET)

# ---------- pattern rules -------------------------------------------------
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c   | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/Utils/%.o: $(UTILS_DIR)/%.c | $(OBJ_DIR)/Utils
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/Negotiation/%.o: $(NEG_DIR)/%.c | $(OBJ_DIR)/Negotiation
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/Auth/%.o: $(AUTH_DIR)/%.c | $(OBJ_DIR)/Auth
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJ_DIR)/Request/%.o: $(REQ_DIR)/%.c | $(OBJ_DIR)/Request
	$(CC) $(CFLAGS) -c $< -o $@

# ---------- directory targets ---------------------------------------------
$(BIN_DIR)            $(OBJ_DIR)             \
$(OBJ_DIR)/Utils      $(OBJ_DIR)/Auth        \
$(OBJ_DIR)/Negotiation $(OBJ_DIR)/Request:
	mkdir -p $@

# ---------- utilities ------------------------------------------------------
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all debug gdb clean
