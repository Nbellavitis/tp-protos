BUILD ?= opt                        # opt (default) | debug
VALID_BUILDS := opt debug safe

ifeq (,$(filter $(BUILD),$(VALID_BUILDS)))
  $(error BUILD must be one of: $(VALID_BUILDS))
endif

MAKE_ARGS := BUILD=$(BUILD)

SERVER_DIR := src/Server
CLIENT_DIR := src/Client

OBJ_DIR := obj
BIN_DIR := bin

.PHONY: all server client clean clean-server clean-client

all: server client

server:
	$(MAKE) -C $(SERVER_DIR) $(MAKE_ARGS)

client:
	$(MAKE) -C $(CLIENT_DIR) $(MAKE_ARGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

clean-server:
	$(MAKE) -C $(SERVER_DIR) clean

clean-client:
	$(MAKE) -C $(CLIENT_DIR) clean
