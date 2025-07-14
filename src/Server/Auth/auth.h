#ifndef AUTH_H
#define AUTH_H
#include "../sock5.h"
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "../users.h"

typedef enum{
    AUTH_SUCCESS = 0,
    AUTH_FAILED = 1,
}auth_status;
user_t * validate_user(const char* username, const char* password);

void authentication_read_init(const unsigned state ,  struct selector_key * key);
unsigned authentication_read(struct selector_key * key);

void authentication_write_init(const unsigned state, struct selector_key *key);
unsigned authentication_write(struct selector_key * key);
unsigned authentication_failure_write(struct selector_key *key);

#endif