//
// Created by nicke on 25/6/2025.
//

#ifndef NEGOTIATION_H
#define NEGOTIATION_H
#include "../sock5.h"
#include "negotiationParser.h"
#include "../parser.h"
unsigned negotiationRead(struct selector_key *key);
unsigned negotiationWrite(struct selector_key *key);
void negotiationReadInit(unsigned state, struct selector_key *key);
void negotiationWriteInit(unsigned state, struct selector_key *key);
#endif //NEGOTIATION_H
