.PHONY: all server client clean clean-server clean-client

SERVER_DIR := src/Server
CLIENT_DIR := src/Client

OBJ_DIR := obj
BIN_DIR := bin

all: server client

server:
	$(MAKE) -C $(SERVER_DIR)

client:
	$(MAKE) -C $(CLIENT_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

clean-server:
	$(MAKE) -C $(SERVER_DIR) clean

clean-client:
	$(MAKE) -C $(CLIENT_DIR) clean

