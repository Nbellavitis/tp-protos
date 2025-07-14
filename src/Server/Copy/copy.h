//
// Created by nicke on 29/6/2025.
//

#ifndef PROTOS_COPY_H
#define PROTOS_COPY_H
#include <netdb.h>
#include "../buffer.h"
#include <stdio.h>
#include <errno.h>
#include "../sock5.h"
// Funciones para el estado COPYING
void socksv5_handle_init(const unsigned state, struct selector_key *key);
unsigned socksv5_handle_read(struct selector_key *key);
unsigned socksv5_handle_write(struct selector_key *key);
void socksv5_handle_close(const unsigned state, struct selector_key *key);
#endif //PROTOS_COPY_H
