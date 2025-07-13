#ifndef AUTH_H
#define AUTH_H
#include "../sock5.h"
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "../users.h"


user_t * validateUser(const char* username, const char* password);
void authenticationReadInit(const unsigned state ,  struct selector_key * key);

unsigned authenticationRead(struct selector_key * key);
unsigned authenticationWrite(struct selector_key * key);
unsigned authenticationFailureWrite(struct selector_key *key);

#endif