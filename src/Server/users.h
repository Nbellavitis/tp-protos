//
// Created by lulos on 7/13/2025.
//

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "constants.h"

#ifndef PROTOCOL_USERS_H
#define PROTOCOL_USERS_H


#define ANON_USER_NAME "anonymous"
#define USER_HISTORY_LOG_BLOCK 10

typedef struct  {
    time_t   ts;                           /* momento en epoch UTC          */
    char     client_ip[INET6_ADDRSTRLEN];  /* origen                        */
    uint16_t client_port;
    char     dst_host[MAX_HOSTNAME_LEN];       /* destino textual               */
    uint16_t dst_port;
    uint8_t  status;                       /* RFC 1928 reply code           */
} access_rec_t;


typedef struct users
{
    char* name;
    char* pass;

    access_rec_t *history;
    size_t        used;
    size_t        cap;
}user_t;


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
