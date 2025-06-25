#ifndef AUTH_H
#define AUTH_H
#include "../sock5.h"

void authenticationReadInit(struct selector_key * key);

unsigned authenticationRead(struct selector_key * key);
unsigned authenticationWrite(struct selector_key * key);
#endif