//
// Created by nicke on 26/6/2025.
//

#ifndef PROTOS_RESOLVER_H
#define PROTOS_RESOLVER_H
#include <netdb.h>
#include "../sock5.h"
#include "../Negotiation/negotiation_parser.h"
#include "../Auth/auth_parser.h"
#include "resolver_parser.h"

typedef struct {
    int gai_error;
    struct addrinfo *result;
} dns_result;

typedef enum{
    SUCCESS = 0x00,
    GENERAL_FAILURE = 0x01,
    NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
}request_reply;
// Funciones para el estado REQ_READ
void request_read_init(const unsigned state, struct selector_key *key);
unsigned request_read(struct selector_key *key);

// Funciones para el estado REQ_WRITE
void request_write_init(const unsigned state, struct selector_key *key);
unsigned request_write(struct selector_key *key);

// Funciones para el estado ADDR_RESOLVE
void address_resolve_init(const unsigned state, struct selector_key *key);
unsigned address_resolve_done(struct selector_key *key, void *data);
// Funciones para el estado CONNECTING
void request_connecting_init(const unsigned state, struct selector_key *key);
unsigned request_connecting(struct selector_key *key);

unsigned address_resolve_write(struct selector_key *key);





#endif //PROTOS_RESOLVER_H
