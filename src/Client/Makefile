OBJ_DIR := ../../obj/client
BIN_DIR := ../../bin/client

CC      := gcc
CFLAGS  := -Wall -Wextra -g -std=c99

MGMT_SRC    := mgmt_client.c
SOCKS5_SRC  := socks5_client.c

MGMT_OBJ    := $(OBJ_DIR)/mgmt_client.o
SOCKS5_OBJ  := $(OBJ_DIR)/socks5_client.o

MGMT_CLIENT := $(BIN_DIR)/mgmt_client
SOCKS5_CLIENT := $(BIN_DIR)/socks5_client

all: $(MGMT_CLIENT) $(SOCKS5_CLIENT)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

$(MGMT_CLIENT): $(MGMT_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(SOCKS5_CLIENT): $(SOCKS5_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

help:
	@echo "Available targets:"
	@echo "  all              - Build both clients"
	@echo "  mgmt_client      - Build management client only"
	@echo "  socks5_client    - Build SOCKS5 client only"
	@echo "  test-mgmt        - Run management client"
	@echo "  test-socks5      - Run SOCKS5 client with default settings"
	@echo "  clean            - Remove built objects and executables"
	@echo ""
	@echo "Executables are placed in: $(BIN_DIR)"
	@echo ""
	@echo "Usage examples:"
	@echo "  Management client: $(MGMT_CLIENT) [host] [port]"
	@echo "    Default: $(MGMT_CLIENT) 127.0.0.1 8080"
	@echo ""
	@echo "  SOCKS5 client: $(SOCKS5_CLIENT) [proxy_host] [proxy_port] [username] [password]"
	@echo "    Default: $(SOCKS5_CLIENT) 127.0.0.1 1080"
	@echo "    With auth: $(SOCKS5_CLIENT) 127.0.0.1 1080 user1 pass1"

.PHONY: all clean test-mgmt test-socks5 help
