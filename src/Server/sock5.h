//
// Created by nicke on 25/6/2025.
//
#ifndef SOCK5_H
#define SOCK5_H
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "selector.h"
#include "stm.h"
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "buffer.h"
#include "Negotiation/negotiation.h"
#include "Negotiation/negotiation_parser.h"
#include "Auth/auth_parser.h"
#include "Auth/auth.h"
#include "Statistics/statistics.h"
#include "Resolver/resolver_parser.h"
#include "args.h"
#include "Copy/copy.h"
#include "ManagementProtocol/management.h"
#include "constants.h"
#include <time.h>
#include "selector.h"

// SOCKS5 server constants
#define MAX_HOSTNAME_LEN        256

#define BUFFER_SIZE BUFFER_SIZE_32K

// Funciones para acceder a usuarios autorizados
struct users* get_authorized_users(void);
int get_num_authorized_users(void);

bool delete_user(const char* username);
struct dns_request {
    struct gaicb req;
    struct client_data * client_data;
    fd_selector selector;
    struct addrinfo hints;
    int fd;
    char port[6]; // Puerto del destino
};
typedef struct client_data {
    struct state_machine stm;
    struct sockaddr_storage client_address;
    bool closed;
    union {
        negotiation_parser  neg_parser;
        auth_parser auth_parser;
        resolver_parser req_parser;
    } client;
    struct addrinfo* origin_resolution;
    struct addrinfo* current_resolution;
    bool resolution_from_getaddrinfo;  // Track memory origin: true=getaddrinfo_a, false=manual malloc
    int client_fd;
    int origin_fd;
    struct  dns_request dns_req;
    int dns_resolution_state;
    struct buffer client_buffer;
    struct buffer origin_buffer;
    uint8_t *in_client_buffer;    // Buffer dinámico
    uint8_t *in_origin_buffer;    // Buffer dinámico
    size_t buffer_size;          // Tamaño actual del buffer
    bool unregistering_origin;
    bool auth_failed; // Indica si la autenticación falló
    // Para logging de acceso
    time_t last_activity;
    user_t * user;
  /*  char username[MAX_USERNAME_LEN];          // Usuario autenticado*/
    char client_ip[INET6_ADDRSTRLEN];   // IP del cliente
    int client_port;             // Puerto del cliente
    char target_host[MAX_HOSTNAME_LEN];       // Host de destino         //@todo hacer MALLOQUABLE
    int target_port;             // Puerto de destino
    uint8_t socks_status;        // Status code SOCKS5

}client_data;

enum socks5State {
    NEGOTIATION_READ = 0,
    NEGOTIATION_WRITE,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    AUTHENTICATION_FAILURE_WRITE,
    REQ_READ,
    ADDR_RESOLVE,
    CONNECTING,
    REQ_WRITE,
    COPYING,
    CLOSED,
    ERROR
};
void socksv5_passive_accept(struct selector_key* key);
void close_connection(struct selector_key *key);
fd_handler * get_socksv5_handler(void);

// Funciones de logging específicas
void log_access_record(client_data *client_data);
void log_password_record(const char *username, const char *protocol, 
                        const char *target_host, int target_port, 
                        const char *discovered_user, const char *discovered_pass);

#endif //SOCK5_H
