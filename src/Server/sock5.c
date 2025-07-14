#include "sock5.h"
#include "selector.h"
#include "stm.h"
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include "Auth/auth_parser.h"
#include "Resolver/resolver.h"
#include "Statistics/statistics.h"
#include "../logger.h"

// Declaración de función externa
extern size_t get_current_buffer_size(void);
extern bool killed;
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static void socksv5_block(struct selector_key *key, void *data);
static void close_arrival(const unsigned state, struct selector_key *key);
static void error_arrival(const unsigned state, struct selector_key *key);

static fd_handler  handler = {
     .handle_read = socksv5_read,
     .handle_write = socksv5_write,
     .handle_close = socksv5_close,
     .handle_block = socksv5_block,
};

static const struct state_definition client_actions[] = {
    {.state = NEGOTIATION_READ, .on_arrival = negotiation_read_init, .on_read_ready = negotiation_read},
    {.state = NEGOTIATION_WRITE, .on_arrival = negotiation_write_init, .on_write_ready = negotiation_write},
    {.state = AUTHENTICATION_READ,.on_arrival = authentication_read_init, .on_read_ready = authentication_read},
    {.state = AUTHENTICATION_WRITE, .on_arrival = authentication_write_init, .on_write_ready = authentication_write},
    {.state = AUTHENTICATION_FAILURE_WRITE, .on_arrival = authentication_write_init, .on_write_ready = authentication_failure_write},
    {.state = REQ_READ,.on_arrival = request_read_init,.on_read_ready = request_read},
    {.state = ADDR_RESOLVE, .on_arrival = address_resolve_init,.on_block_ready = address_resolve_done}, //todo cambiar nombre!?
    {.state = CONNECTING, .on_arrival = NULL, .on_write_ready = request_connecting},
    {.state = REQ_WRITE, .on_arrival = request_write_init, .on_write_ready = request_write},
    {.state = COPYING,   .on_arrival = socksv5_handle_init,.on_read_ready = socksv5_handle_read,.on_write_ready = socksv5_handle_write,.on_departure = socksv5_handle_close},
    {.state = CLOSED, .on_arrival = close_arrival},
    {.state=ERROR, .on_arrival = error_arrival}
};
void socksv5_passive_accept(struct selector_key* key){
    struct sockaddr_storage client_address;
    socklen_t client_address_len = sizeof(client_address);
    int new_client_socket = accept(key->fd, (struct sockaddr*)&client_address, &client_address_len);
    if (new_client_socket < 0) {
        perror("Error accepting new client connection");
        return;
    }
    if (new_client_socket >= FD_SETSIZE) {
        LOG_ERROR("%s" ,"New client socket exceeds maximum file descriptor limit");
        close(new_client_socket);
        return;
    }
    ClientData * client_data = calloc(1,sizeof(struct ClientData));
    if (client_data == NULL) {
        perror("Error allocating memory for client data");
        close(new_client_socket);
        return;
    }
    LOG_DEBUG("New client connected on socket %d", new_client_socket);
    stats_connection_opened();
    client_data->stm.initial = NEGOTIATION_READ;
    client_data->stm.max_state = ERROR;
    client_data->closed = false;
    client_data->stm.states = client_actions;
    client_data->client_fd = new_client_socket;
    client_data->client_address = client_address;
    client_data->origin_fd = -1;
    client_data->origin_resolution = NULL;
    client_data->resolution_from_getaddrinfo = false;
    client_data->connection_ready = 0;
    client_data->dns_resolution_state = 0;
    client_data->unregistering_origin = false;
    client_data->auth_failed = false;
    // Inicializar campos de logging
    client_data->user = NULL;
    memset(client_data->client_ip, 0, sizeof(client_data->client_ip));
    memset(client_data->target_host, 0, sizeof(client_data->target_host));
    client_data->client_port = 0;
    client_data->target_port = 0;
    client_data->socks_status = 0;
    
    // Extraer IP y puerto del cliente
    if (client_address.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_address;
        inet_ntop(AF_INET, &addr_in->sin_addr, client_data->client_ip, INET6_ADDRSTRLEN);
        client_data->client_port = ntohs(addr_in->sin_port);
    } else if (client_address.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&client_address;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_data->client_ip, INET6_ADDRSTRLEN);
        client_data->client_port = ntohs(addr_in6->sin6_port);
    }
    // Asignar buffers dinámicos con el tamaño actual
    client_data->buffer_size = get_current_buffer_size();
    client_data->in_client_buffer = malloc(client_data->buffer_size);
    client_data->in_origin_buffer = malloc(client_data->buffer_size);
    
    if (client_data->in_client_buffer == NULL || client_data->in_origin_buffer == NULL) {
        LOG_ERROR("Failed to allocate dynamic buffers for client");
        if (client_data->in_client_buffer) free(client_data->in_client_buffer);
        if (client_data->in_origin_buffer) free(client_data->in_origin_buffer);
        free(client_data);
        close(new_client_socket);
        return;
    }
    
    buffer_init(&client_data->client_buffer, client_data->buffer_size, client_data->in_client_buffer);
    buffer_init(&client_data->origin_buffer, client_data->buffer_size, client_data->in_origin_buffer);

    stm_init(&client_data->stm);
    selector_status ss = selector_register(key->s, new_client_socket, &handler, OP_READ, client_data);
    if (ss != SELECTOR_SUCCESS) {
        free(client_data->in_client_buffer);
        free(client_data->in_origin_buffer);
        free(client_data);
        close(new_client_socket);
        return;
    }
    if(selector_fd_set_nio(new_client_socket) == -1) { //todo check si esta bien
        LOG_ERROR("Failed to set non-blocking mode for new client socket %d", new_client_socket);
        free(client_data->in_client_buffer);
        free(client_data->in_origin_buffer);
        free(client_data);
        close(new_client_socket);
    }

}

static void socksv5_read(struct selector_key *key) {
    ClientData *client_data = (ClientData *)key->data;

    LOG_DEBUG("SOCKS5_READ: Reading data from socket %d", key->fd);

    const enum socks5State state = stm_handler_read(&client_data->stm, key);
    if (state == ERROR || state == CLOSED) {
        close_connection(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    if (key == NULL) {
        LOG_ERROR("%s" ,"socksv5_write: key is NULL");
        return;
    }
    if (key->data == NULL) {
        LOG_ERROR("%s" ,"socksv5_write: key->data is NULL");
        return;
    }
    ClientData *client_data = (ClientData *)key->data;
    const enum socks5State state = stm_handler_write(&client_data->stm, key);
    LOG_DEBUG("socksv5_write: stm_handler_write returned: %d", state);
    if (state == ERROR || state == CLOSED) {
        close_connection(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    ClientData *client_data = (ClientData *)key->data;

    if (client_data->unregistering_origin) {
        return;
    }

    stm_handler_close(&client_data->stm, key);
    close_connection(key);
}
static void socksv5_block(struct selector_key *key, void *data) {
    (void)data;

    if (key == NULL) {
        LOG_ERROR("%s" ,"socksv5_block: key is NULL");
        return;
    }
    if (key->data == NULL) {
        LOG_ERROR("%s" ,"socksv5_block: key->data is NULL");
        return;
    }
    ClientData *client_data = (ClientData *)key->data;
    const enum socks5State state = stm_handler_block(&client_data->stm, key,data);
    LOG_DEBUG("socksv5_block: stm_handler_block returned: %d", state);
    if (state == ERROR || state == CLOSED) {
        close_connection(key);
        return;
    }
}
void close_connection(struct selector_key *key) {
    ClientData *client_data = (ClientData *)key->data;
    if (client_data->closed) {
        return; // ya fue cerrado
    }
    stats_connection_closed();
    client_data->closed = true;
    if (killed) {

        if (client_data->origin_fd >= 0 && client_data->origin_fd != key->fd) {
            selector_unregister_fd(key->s, client_data->origin_fd);
            close(client_data->origin_fd);
        }
        if (client_data->client_fd >= 0 && client_data->client_fd != key->fd) {
            selector_unregister_fd(key->s, client_data->client_fd);
            close(client_data->client_fd);
        }
    } else {

        if (client_data->origin_fd >= 0) {
            selector_unregister_fd(key->s, client_data->origin_fd);
            close(client_data->origin_fd);
        }
        if (client_data->client_fd >= 0) {
            selector_unregister_fd(key->s, client_data->client_fd);
            close(client_data->client_fd);
        }
    }

    if (client_data->dns_resolution_state == 1) {
        // Cancelar resolución pendiente
        struct gaicb *reqs[] = { &client_data->dns_req.req };
        gai_cancel(reqs[0]);
    }

    // Cleanup DNS resolution memory
    if (client_data->origin_resolution != NULL) {
        if (client_data->resolution_from_getaddrinfo) {
            // Memoria de getaddrinfo_a() - usar freeaddrinfo
            freeaddrinfo(client_data->origin_resolution);
        } else {
            // Memoria manual - liberar ai_addr y estructura por separado
            if (client_data->origin_resolution->ai_addr != NULL) {
                free(client_data->origin_resolution->ai_addr);
            }
            free(client_data->origin_resolution);
        }
    }

    // Registro de acceso antes de liberar client_data
    log_access_record(client_data);

    // Liberar buffers dinámicos
    if (client_data->in_client_buffer != NULL) {
        free(client_data->in_client_buffer);
    }
    if (client_data->in_origin_buffer != NULL) {
        free(client_data->in_origin_buffer);
    }

    free(client_data);
}



void log_store_for_user(const ClientData *cd)
{
    if (!cd) return;

    user_t *u = cd->user ? cd->user : get_anon_user();
    if (!u) return;

    if (u->cap == u->used) {
        LOG_DEBUG("Doing a realloc of the USER %s history", u->name);
        size_t new_cap = u->cap + USER_HISTORY_LOG_BLOCK;
        access_rec_t *tmp = realloc(u->history,
                                    new_cap * sizeof(access_rec_t));
        if (!tmp) {
            LOG_ERROR("access_log: realloc failed (user=%s)",
                      u->name ? u->name : "anonymous");
            return;   /* se descarta el registro si no hay memoria */  //@todo esta bien?
        }
        u->history = tmp;
        u->cap     = new_cap;
    }

    access_rec_t *rec = &u->history[u->used++];
    rec->ts          = time(NULL);

    strncpy(rec->client_ip, cd->client_ip, sizeof(rec->client_ip));
    rec->client_ip[sizeof(rec->client_ip)-1] = '\0';

    rec->client_port = (uint16_t)cd->client_port;

    strncpy(rec->dst_host, cd->target_host, sizeof(rec->dst_host));
    rec->dst_host[sizeof(rec->dst_host)-1] = '\0';

    rec->dst_port = (uint16_t)cd->target_port;
    rec->status   = cd->socks_status;
}



void log_access_record(ClientData *client_data) {
    if (!client_data) return;
    
    // Fecha en formato ISO-8601
    time_t now = time(NULL);
    struct tm *utc_tm = gmtime(&now);
    char timestamp[TIMESTAMP_BUFFER_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", utc_tm);
    
    // REGISTRO DE ACCESO: fecha\tusuario\tA\tip_origen\tpuerto_origen\tdestino\tpuerto_destino\tstatus
    if (client_data->auth_failed) {
        LOG_INFO("%-25s  %-12s  %-2s  %-17s  %-6d  %-25s  %-6d  %-12s",
                 timestamp,
                 client_data->user ? client_data->user->name : "anonymous",
                 "A",
                 client_data->client_ip[0] ? client_data->client_ip : "unknown",
                 client_data->client_port,
                 client_data->target_host[0] ? client_data->target_host : "unknown",
                 client_data->target_port,
                 "0X01 (RFC 1929 - Authentication failed)");
    } else {
        LOG_INFO("%-25s  %-12s  %-2s  %-17s  %-6d  %-25s  %-6d  %-2d",
                 timestamp,
                 client_data->user ? client_data->user->name : "anonymous",
                 "A",
                 client_data->client_ip[0] ? client_data->client_ip : "unknown",
                 client_data->client_port,
                 client_data->target_host[0] ? client_data->target_host : "unknown",
                 client_data->target_port,
                 client_data->socks_status);
    }

    log_store_for_user(client_data);

}

void log_password_record(const char *username, const char *protocol, 
                        const char *target_host, int target_port, 
                        const char *discovered_user, const char *discovered_pass) {
    // Fecha en formato ISO-8601
    time_t now = time(NULL);
    struct tm *utc_tm = gmtime(&now);
    char timestamp[TIMESTAMP_BUFFER_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", utc_tm);
    
    // REGISTRO DE PASSWORDS: fecha\tusuario\tP\tprotocolo\tdestino\tpuerto_destino\tusuario_desc\tpass_desc
    LOG_INFO("%s\t%s\tP\t%s\t%s\t%d\t%s\t%s",
           timestamp,
           username ? username : "anonymous",
           protocol,
           target_host,
           target_port,
           discovered_user,
           discovered_pass);
}

fd_handler * get_socksv5_handler(void) {
    return &handler;
}


//@TODO tiene sentido esto?
static void close_arrival(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("Arriving at CLOSED state (state = %d, key = %p)", state, (void *)key);
}

static void error_arrival(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("Arriving at ERROR state (state = %d, key = %p)", state, (void *)key);
}