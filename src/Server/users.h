//
// Created by lulos on 7/13/2025.
//

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "sock5.h"

#ifndef _USERS_H
#define _USERS_H

#define ANON_USER_NAME "anonymous"

#define USER_HISTORY_LOG_BLOCK 10
#define MAX_HOST_LEN 256  //@todo cambiar a otro archivo. Borrar magic number de los otros.
#define MAX_LOG_HOSTNAME_LEN 70

typedef struct  {
    time_t   ts;                           /* momento en epoch UTC          */
    char     client_ip[INET6_ADDRSTRLEN];  /* origen                        */
    uint16_t client_port;
    char     dst_host[MAX_HOST_LEN];       /* destino textual               */
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


#endif
