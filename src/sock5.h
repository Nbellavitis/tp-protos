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
#include "Logging/statistics.h"
#include "Resolver/resolverParser.h"
#include "args.h"
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
    int fd;
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
    int clientFd;
    int originFd;
    struct  dns_request dns_req;
    int dns_resolution_state;
    struct buffer clientBuffer;
    struct buffer originBuffer;
    uint8_t inClientBuffer[BUFFER_SIZE];
    uint8_t inOriginBuffer[BUFFER_SIZE];
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
#endif //SOCK5_H
