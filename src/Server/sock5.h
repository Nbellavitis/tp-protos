//
// Created by nicke on 25/6/2025.
//
#ifndef SOCK5_H
#define SOCK5_H
#define _GNU_SOURCE
#include <netdb.h>
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
#include "Negotiation/negotiationParser.h"
#include "Auth/authParser.h"
#include "Auth/auth.h"
#include "Statistics/statistics.h"
#include "Resolver/resolverParser.h"
#include "args.h"
#include "Copy/copy.h"
#define BUFFER_SIZE 32768

// Funciones para acceder a usuarios autorizados
struct users* get_authorized_users(void);
int get_num_authorized_users(void);
bool add_user(const char* username, const char* password);
bool delete_user(const char* username);
struct dns_request {
    struct gaicb req;
    struct ClientData * clientData;
    fd_selector selector;
    struct addrinfo hints;
    int fd;
    char port[6]; // Puerto del destino
};
typedef struct ClientData {
    struct state_machine stm;
    struct sockaddr_storage clientAddress;
    bool closed;
    union {
        negotiation_parser  negParser;
        auth_parser authParser;
        resolver_parser reqParser;
    } client;
    struct addrinfo* originResolution;
    bool resolution_from_getaddrinfo;  // Track memory origin: true=getaddrinfo_a, false=manual malloc
    int clientFd;
    int originFd;
    struct  dns_request dns_req;
    int dns_resolution_state;
    int connection_ready;
    struct buffer clientBuffer;
    struct buffer originBuffer;
    uint8_t inClientBuffer[BUFFER_SIZE];
    uint8_t inOriginBuffer[BUFFER_SIZE];
    
    // Para logging de acceso  
    char username[256];          // Usuario autenticado
    char client_ip[INET6_ADDRSTRLEN];   // IP del cliente
    int client_port;             // Puerto del cliente
    char target_host[256];       // Host de destino
    int target_port;             // Puerto de destino
    uint8_t socks_status;        // Status code SOCKS5

    bool unregistering_origin;
}ClientData;

enum socks5State {
    NEGOTIATION_READ = 0,
    NEGOTIATION_WRITE,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    REQ_READ,
    ADDR_RESOLVE,
    CONNECTING,
    REQ_WRITE,
    COPYING,
    CLOSED,
    ERROR
};
void socksv5PassiveAccept(struct selector_key* key);
void closeConnection(struct selector_key *key);
fd_handler * getSocksv5Handler(void);

// Funciones de logging específicas
void log_access_record(ClientData *clientData);
void log_password_record(const char *username, const char *protocol, 
                        const char *target_host, int target_port, 
                        const char *discovered_user, const char *discovered_pass);

#endif //SOCK5_H
