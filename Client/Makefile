CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99

# Targets
MGMT_CLIENT = mgmt_client
SOCKS5_CLIENT = socks5_client

# Sources
MGMT_SRC = mgmt_client.c
SOCKS5_SRC = socks5_client.c

all: $(MGMT_CLIENT) $(SOCKS5_CLIENT)

$(MGMT_CLIENT): $(MGMT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(SOCKS5_CLIENT): $(SOCKS5_SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(MGMT_CLIENT) $(SOCKS5_CLIENT)

test-mgmt: $(MGMT_CLIENT)
	@echo "Starting Management Client..."
	./$(MGMT_CLIENT)

test-socks5: $(SOCKS5_CLIENT)
	@echo "Starting SOCKS5 Client..."
	./$(SOCKS5_CLIENT)

help:
	@echo "Available targets:"
	@echo "  all         - Build both clients"
	@echo "  mgmt_client - Build management client only"
	@echo "  socks5_client - Build SOCKS5 client only"
	@echo "  test-mgmt   - Run management client"
	@echo "  test-socks5 - Run SOCKS5 client with default settings"
	@echo "  clean       - Remove built executables"
	@echo ""
	@echo "Usage examples:"
	@echo "  Management client: ./mgmt_client [host] [port]"
	@echo "    Default: ./mgmt_client 127.0.0.1 8080"
	@echo ""
	@echo "  SOCKS5 client: ./socks5_client [proxy_host] [proxy_port] [username] [password]"
	@echo "    Default: ./socks5_client 127.0.0.1 1080"
	@echo "    With auth: ./socks5_client 127.0.0.1 1080 user1 pass1"

.PHONY: all clean test-mgmt test-socks5 help