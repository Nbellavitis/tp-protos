# ==================================================================
#  Management and SOCKS5 Clients with Client Utilities
#  ▸ OPT profile (production) by default
#  ▸ DEBUG/SAFE profile with `make BUILD=debug`
# ==================================================================

include ../Makefile.inc

CC ?= gcc

# Build profile selection
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
CLIENT_UTILS  := client_utils.c

MGMT_OBJ      := $(OBJ_DIR)/mgmt_client.o
SOCKS5_OBJ    := $(OBJ_DIR)/socks5_client.o
CLIENT_UTILS_OBJ := $(OBJ_DIR)/client_utils.o

MGMT_CLIENT   := $(BIN_DIR)/mgmt_client
SOCKS5_CLIENT := $(BIN_DIR)/socks5_client

INCLUDES      := -I.

all: $(MGMT_CLIENT) $(SOCKS5_CLIENT)

$(MGMT_CLIENT): $(MGMT_OBJ) $(CLIENT_UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(SOCKS5_CLIENT): $(SOCKS5_OBJ) $(CLIENT_UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)


.PHONY: all clean