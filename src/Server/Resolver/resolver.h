//
// Created by nicke on 26/6/2025.
//

#ifndef PROTOS_RESOLVER_H
#define PROTOS_RESOLVER_H
#define _GNU_SOURCE
#include <netdb.h>
#include "../sock5.h"
#include "../Negotiation/negotiationParser.h"
#include "../Auth/authParser.h"
#include "resolverParser.h"

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
void requestReadInit(const unsigned state, struct selector_key *key);
unsigned requestRead(struct selector_key *key);

// Funciones para el estado REQ_WRITE
unsigned requestWrite(const struct selector_key *key);

// Funciones para el estado ADDR_RESOLVE
void addressResolveInit(const unsigned state, struct selector_key *key);
unsigned addressResolveDone(struct selector_key *key);

// Funciones para el estado CONNECTING
void requestConnectingInit(const unsigned state, struct selector_key *key);
unsigned requestConnecting(struct selector_key *key);





#endif //PROTOS_RESOLVER_H
