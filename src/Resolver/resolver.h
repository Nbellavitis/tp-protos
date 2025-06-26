//
// Created by nicke on 26/6/2025.
//

#ifndef PROTOS_RESOLVER_H
#define PROTOS_RESOLVER_H
#include "../sock5.h"
#include "../Negotiation/negotiationParser.h"
#include "../Auth/authParser.h"
#include "resolverParser.h"

// Funciones para el estado REQ_READ
void requestReadInit(const unsigned state, struct selector_key *key);
unsigned requestRead(struct selector_key *key);

// Funciones para el estado REQ_WRITE
unsigned requestWrite(struct selector_key *key);

// Funciones para el estado ADDR_RESOLVE
void addressResolveInit(const unsigned state, struct selector_key *key);
unsigned addressResolveDone(struct selector_key *key);

// Funciones para el estado CONNECTING
void requestConnectingInit(const unsigned state, struct selector_key *key);
unsigned requestConnecting(struct selector_key *key);

// Funciones para el estado COPYING
void socksv5HandleInit(const unsigned state, struct selector_key *key);
unsigned socksv5HandleRead(struct selector_key *key);
unsigned socksv5HandleWrite(struct selector_key *key);
void socksv5HandleClose(const unsigned state, struct selector_key *key);

// Funciones para los estados finales
void closeArrival(const unsigned state, struct selector_key *key);
void errorArrival(const unsigned state, struct selector_key *key);

#endif //PROTOS_RESOLVER_H
