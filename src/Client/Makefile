# ==================================================================
#  Cliente de Management y SOCKS5
#  ▸ Perfil OPT (producción) por defecto
#  ▸ Perfil DEBUG/SAFE con  make BUILD=debug
# ==================================================================


include ../Makefile.inc

CC ?= gcc

ifeq ($(filter $(BUILD),debug safe),)
  CFLAGS  := $(CFLAGS_OPT)
  LDFLAGS := $(LDFLAGS_OPT)
else
  CFLAGS  := $(CFLAGS_DEBUG)
  LDFLAGS := $(LDFLAGS_DEBUG)
endif

OBJ_DIR       := ../../obj/client
BIN_DIR       := ../../bin/client

MGMT_SRC      := mgmt_client.c
SOCKS5_SRC    := socks5_client.c

MGMT_OBJ      := $(OBJ_DIR)/mgmt_client.o
SOCKS5_OBJ    := $(OBJ_DIR)/socks5_client.o

MGMT_CLIENT   := $(BIN_DIR)/mgmt_client
SOCKS5_CLIENT := $(BIN_DIR)/socks5_client

all: $(MGMT_CLIENT) $(SOCKS5_CLIENT)

$(MGMT_CLIENT): $(MGMT_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(SOCKS5_CLIENT): $(SOCKS5_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

help:
	@echo "Targets:"
	@echo "  all           – build both clients  (default, OPT profile)"
	@echo "  clean         – remove objects and executables"
	@echo ""
	@echo "Profiles:"
	@echo "  make              (OPT)   – fast, logs INFO"
	@echo "  make BUILD=debug  (SAFE)  – ASan + logs DEBUG"

.PHONY: all clean help
