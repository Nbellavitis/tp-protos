//
// Created by lulos on 7/14/2025.
//

#include "management_cmds.h"

#include "management.h"
#include "../Statistics/statistics.h"
#include "../args.h"
#include "../../logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bits/types/struct_tm.h>
#include <time.h>


static void cmd_stats(ManagementData *);
static void cmd_list_users(ManagementData *);
static void cmd_add_user(ManagementData *);
static void cmd_delete_user(ManagementData *);
static void cmd_change_password(ManagementData *);
static void cmd_set_buffer_size(ManagementData *);
static void cmd_get_buffer_info(ManagementData *);
static void cmd_set_auth_method(ManagementData *);
static void cmd_get_auth_method(ManagementData *);
static void cmd_get_log_by_user(ManagementData *);




static void send_status_only(ManagementData *md, uint8_t status)
{
    /* encabezado de 3 bytes (VER|STATUS|LEN=0) */
    send_management_response(&md->response_buffer, status, "");
}

static bool size_allowed(uint32_t v)
{
    for (uint8_t i = 0; i < BUFFER_SIZE_CNT; i++)
        if (buffer_sizes[i] == v) return true;
    return false;
}

static void cmd_stats(ManagementData *md)
{
    uint32_t vals[STATS_FIELDS] = {
            stats_get_connections_opened(),
            stats_get_connections_closed(),
            stats_get_current_connections(),
            stats_get_client_bytes(),
            stats_get_origin_bytes()
    };
    for (int i = 0; i < STATS_FIELDS; i++)
        vals[i] = htonl(vals[i]);

    send_management_response_raw(&md->response_buffer,
                                 STATUS_OK,
                                 (uint8_t *)vals,
                                 STATS_PAYLOAD_BYTES);
}

static void cmd_list_users(ManagementData *md)
{
    struct users *u = get_authorized_users();
    uint8_t n = (uint8_t)get_num_authorized_users();

    uint8_t pl[MAX_MGMT_PAYLOAD_LEN];
    pl[0] = n;
    size_t off = 1;

    for (uint8_t i = 0; i < n && off < MAX_MGMT_PAYLOAD_LEN; i++) {
        size_t l = strlen(u[i].name) + 1;           /* incluye NUL */
        if (off + l > MAX_MGMT_PAYLOAD_LEN) break;
        memcpy(pl + off, u[i].name, l);
        off += l;
    }
    send_management_response_raw(&md->response_buffer, STATUS_OK, pl, off);
}


void cmd_add_user(ManagementData *md)
{
    char *c = strchr(md->parser.payload, ':');
    if (!c) { send_status_only(md, STATUS_INVALID_FORMAT); return; }

    *c = '\0';
    add_user_result_t r = add_user(md->parser.payload, c+1);

    switch (r) {
        case ADD_OK:        send_status_only(md, STATUS_OK);              break;
        case ADD_EXISTS:    send_status_only(md, STATUS_ALREADY_EXISTS);  break;
        case ADD_FULL:      send_status_only(md, STATUS_FULL);            break;
        case ADD_INVALID:   send_status_only(md, STATUS_INVALID_FORMAT);  break;
        case ADD_RESERVED:  send_status_only(md, STATUS_RESERVED_USER);   break;
        default:            send_status_only(md, STATUS_ERROR);           break;
    }
}

static void cmd_delete_user(ManagementData *md)
{
    const char *user = md->parser.payload;

    if (*user == '\0') {
        send_status_only(md, STATUS_ERROR);
        return;
    }

    if (delete_user(user)){
        send_status_only(md, STATUS_OK);
        return;
    }
    send_status_only(md, STATUS_NOT_FOUND);
}

static void cmd_change_password(ManagementData *md)
{
    char *colon = strchr(md->parser.payload, ':');
    if (!colon) { send_status_only(md, STATUS_INVALID_FORMAT); return; }

    *colon = '\0';
    char *user = md->parser.payload;
    char *newp = colon + 1;

    if (*user == '\0' || *newp == '\0'){
        send_status_only(md, STATUS_INVALID_FORMAT);
        return;
    }
    if (change_user_password(user, newp)){
        send_status_only(md, STATUS_OK);
        return;
    }
    send_status_only(md, STATUS_NOT_FOUND);
}

static void cmd_set_buffer_size(ManagementData *md)
{
    if (md->parser.payload_len != 4) { send_status_only(md, STATUS_INVALID_FORMAT); return; }

    uint32_t net; memcpy(&net, md->parser.payload, 4);
    uint32_t v = ntohl(net);

    if (!size_allowed(v)){
        send_status_only(md, STATUS_NOT_ALLOWED);
        return;
    }
    if (set_buffer_size(v)){
        send_status_only(md, STATUS_OK);
        return;
    }

    send_status_only(md, STATUS_ERROR);
}

//static void cmd_get_buffer_info(ManagementData *md)
//{
//    uint8_t pl[1 + 4 + 4 * BUFFER_SIZE_CNT];
//    uint32_t cur = htonl((uint32_t)get_current_buffer_size());
//
//    memcpy(pl, &cur, 4);
//    pl[4] = BUFFER_SIZE_CNT;
//
//    for (uint8_t i = 0; i < BUFFER_SIZE_CNT; i++)
//        *(uint32_t *)(pl + 5 + i * 4) = htonl(buffer_sizes[i]);
//
//    send_management_response_raw(&md->response_buffer,
//                                 STATUS_OK,
//                                 pl,
//                                 5 + 4 * BUFFER_SIZE_CNT);
//}

static void cmd_get_buffer_info(ManagementData *md)
{
    uint32_t cur = htonl((uint32_t)get_current_buffer_size());

    send_management_response_raw(&md->response_buffer,
                                 STATUS_OK,
                                 (uint8_t *)&cur,
                                 4);
}


static void cmd_set_auth_method(ManagementData *md)
{
    if (strcmp(md->parser.payload, "NOAUTH") == 0) {
        set_auth_method(NOAUTH);
        send_status_only(md, STATUS_OK);
        return;
    }else if (strcmp(md->parser.payload, "AUTH") == 0) {
        set_auth_method(AUTH);
        send_status_only(md, STATUS_OK);
        return;
    }
    send_status_only(md, STATUS_INVALID_FORMAT);
}

static void cmd_get_auth_method(ManagementData *md)
{
    uint8_t byte = (get_auth_method() == NOAUTH) ? 0x00 : 0x01;
    send_management_response_raw(&md->response_buffer,
                                 STATUS_OK,
                                 &byte,
                                 1);
}





//@TODO: por como esta definido el protocolo hay veces que se trunca la respuesta!!!!. El maximo del payload es 256 y el maximo de host lenght es eso tambien! hay que agrandar el payload y cambiar un poco esta funcion.
static void cmd_get_log_by_user(ManagementData *md)
{
    /* 0)  Autenticación obligatoria */
    if (!md->authenticated) {
        send_management_response(&md->response_buffer,
                                 STATUS_AUTH_REQUIRED,
                                 "Authentication required");
        return;
    }

    /* 1)  Usuario en payload */
    char uname[MAX_USERNAME_LEN + 1];
    size_t ulen = md->parser.payload_len > MAX_USERNAME_LEN
                  ? MAX_USERNAME_LEN
                  : md->parser.payload_len;
    memcpy(uname, md->parser.payload, ulen);
    uname[ulen] = '\0';

    /* 2)  Buscar el bucket */
    user_t *u = NULL;
    if (strcmp(uname, "anonymous") == 0) {
        u = get_anon_user();
    } else {
        user_t *tbl = get_authorized_users();
        int n = get_num_authorized_users();
        for (int i = 0; i < n; i++) {
            if (tbl[i].name && strcmp(tbl[i].name, uname) == 0) {
                u = &tbl[i];
                break;
            }
        }
    }
    if (!u) {     /* usuario inexistente */
        send_management_response(&md->response_buffer,
                                 STATUS_NOT_FOUND,
                                 "User not found");
        return;
    }

    /* 3)  Armar payload truncado (≤255 B) */
    char  payload[MGMT_PAYLOAD_SIZE];       /* MAX_MGMT_PAYLOAD_LEN bytes + '\0' */
    size_t plen = 0;

    char   ts[TIMESTAMP_BUFFER_SIZE], line[LOG_LINE_SIZE];
    struct tm tm_;

    for (size_t i = 0; i < u->used && plen < MAX_MGMT_PAYLOAD_LEN; i++) {
        gmtime_r(&u->history[i].ts, &tm_);
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm_);

        /* espacio disponible, dejando 1 para '\0' */
        size_t room = MAX_MGMT_PAYLOAD_LEN - plen;
        int n = snprintf(payload + plen, room + 1,
                         "%s\t%s\t%u\t%s\t%u\t0x%02X\n",
                         ts,
                         u->history[i].client_ip,
                         u->history[i].client_port,
                         u->history[i].dst_host,
                         u->history[i].dst_port,
                         u->history[i].status);

        if (n < 0) continue;          /* error improbable */
        if ((size_t)n >= room) {      /* se truncó la línea */
            plen = MAX_MGMT_PAYLOAD_LEN;               /* llenamos el cupo y salimos */
            break;
        }
        plen += (size_t)n;            /* línea completa añadida */
    }
    payload[plen] = '\0';             /* asegurar terminación */

    /* 4)  Responder STATUS_OK con el payload (truncado o no) */
    send_management_response(&md->response_buffer, STATUS_OK, payload);
}



static const mgmt_cmd_fn mgmt_cmd_table[] = {
        (cmd_stats),            /* 0x02 */
        (cmd_list_users),       /* 0x03 */
        (cmd_add_user),         /* 0x04 */
        (cmd_delete_user),      /* 0x05 */
        (cmd_change_password),  /* 0x06 */
        (cmd_set_buffer_size),  /* 0x07 */
        (cmd_get_buffer_info),  /* 0x08 */
        (cmd_set_auth_method),  /* 0x09 */
        (cmd_get_auth_method),  /* 0x0A */
        (cmd_get_log_by_user)   /* 0x0B */
};
void mgmt_dispatch_command(ManagementData *md)
{
    uint8_t cmd = md->parser.command;

    if (cmd >= CMD_STATS && cmd <= CMD_GET_LOG_BY_USER) {
        mgmt_cmd_fn fn = mgmt_cmd_table[cmd - CMD_STATS];
        fn(md);

    } else if (cmd == CMD_AUTH) {
        send_management_response(&md->response_buffer,
                                 STATUS_ERROR,
                                 "Invalid operation: already authenticated");  //@TODO check

    } else {
        send_management_response(&md->response_buffer,
                                 STATUS_ERROR,
                                 "Unknown command");                        // @Todo check. Podria cambiar el error code.
    }
}
