#ifndef REQUEST_H
#define REQUEST_H
#include "../sock5.h"

void requestReadInit(unsigned state, struct selector_key *key);
unsigned requestRead(struct selector_key *key);
unsigned requestWrite(struct selector_key *key);

// Para la resolución DNS
unsigned addressResolveDone(struct selector_key *key);

// Para la conexión al servidor destino
void requestConnectingInit(unsigned state, struct selector_key *key);
unsigned requestConnecting(struct selector_key *key);

#endif