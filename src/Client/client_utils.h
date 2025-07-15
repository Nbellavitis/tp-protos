#ifndef _CLIENT_UTILS_H
#define _CLIENT_UTILS_H
#include <sys/types.h>
#include <netdb.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../management_constants.h"
#include "client_utils.h"



#define DEFAULT_MGMT_HOST          "127.0.0.1"
#define DEFAULT_MGMT_PORT          8080
#define DEFAULT_SOCKS5_HOST "127.0.0.1"
#define DEFAULT_SOCKS5_PORT 1080
#define INPUT_SMALL_BUF            32


#define MAX_PORT_NUMBER 65535



void prompt_server_config(char *host, size_t host_sz, int *port, bool mgmt);
int read_line(const char *prompt, char *buf, size_t n);
int ask_choice(const char *prompt, int min, int max);
int connect_server(const char *server_host, int server_port, int *socket_fd);

#endif
