//
// Created by nicke on 29/6/2025.
//

#ifndef PROTOS_COPY_H
#define PROTOS_COPY_H
#define _GNU_SOURCE
#include <netdb.h>
#include "../buffer.h"
#include <stdio.h>
#include <errno.h>
#include "../sock5.h"
// Funciones para el estado COPYING
void socksv5HandleInit(const unsigned state, struct selector_key *key);
unsigned socksv5HandleRead(struct selector_key *key);
unsigned socksv5HandleWrite(struct selector_key *key);
void socksv5HandleClose(const unsigned state, struct selector_key *key);
#endif //PROTOS_COPY_H
