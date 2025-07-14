
#include <stdbool.h>
#include "Auth/auth.h"
#include "constants.h"

#ifndef MAIN_H
#define MAIN_H

typedef enum {
    ADD_OK = 0,        /* usuario añadido                    */
    ADD_INVALID,       /* campos vacíos o >límite           */
    ADD_EXISTS,        /* ya existe                          */
    ADD_FULL,          /* tabla llena                        */
    ADD_MEM_ERROR,     /* malloc falló                       */
    ADD_RESERVED       /* nombre reservado (“anonymous”)     */
} add_user_result_t;

struct users* get_authorized_users(void);
int get_num_authorized_users(void);
add_user_result_t add_user(const char* username, const char* password);
bool delete_user(const char* username);
bool change_user_password(const char* username, const char* new_password);
user_t * get_anon_user(void);
#endif