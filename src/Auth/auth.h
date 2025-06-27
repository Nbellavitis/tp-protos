#ifndef AUTH_H
#define AUTH_H
#define _GNU_SOURCE
#include "../sock5.h"

void authenticationReadInit(unsigned state ,struct selector_key * key);

unsigned authenticationRead(struct selector_key * key);
unsigned authenticationWrite(struct selector_key * key);
#endif