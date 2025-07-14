//
// Created by nicke on 25/6/2025.
//

#ifndef NEGOTIATION_H
#define NEGOTIATION_H
#include "../sock5.h"
#include "negotiation_parser.h"
#include "../parser.h"
unsigned negotiation_read(struct selector_key *key);
unsigned negotiation_write(struct selector_key *key);
void negotiation_read_init(unsigned state, struct selector_key *key);
void negotiation_write_init(unsigned state, struct selector_key *key);
#endif //NEGOTIATION_H
