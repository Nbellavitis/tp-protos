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
#include "Auth/authParser.h"
#include "Resolver/resolver.h"
#include "Statistics/statistics.h"
#include "../logger.h"

// Declaración de función externa
extern size_t get_current_buffer_size(void);
extern bool killed;
static void socksv5Read(struct selector_key *key);
static void socksv5Write(struct selector_key *key);
static void socksv5Close(struct selector_key *key);
static void socksv5Block(struct selector_key *key);
static void closeArrival(const unsigned state, struct selector_key *key);
static void errorArrival(const unsigned state, struct selector_key *key);

static fd_handler  handler = {
     .handle_read = socksv5Read,
     .handle_write = socksv5Write,
     .handle_close = socksv5Close,
     .handle_block = socksv5Block,
};

static const struct state_definition clientActions[] = {
    {.state = NEGOTIATION_READ, .on_arrival = negotiationReadInit, .on_read_ready = negotiationRead},
    {.state = NEGOTIATION_WRITE,.on_write_ready = negotiationWrite},
    {.state = AUTHENTICATION_READ,.on_arrival = authenticationReadInit, .on_read_ready = authenticationRead},
    {.state = AUTHENTICATION_WRITE, .on_write_ready = authenticationWrite},
    {.state = AUTHENTICATION_FAILURE_WRITE, .on_write_ready = authenticationFailureWrite},
    {.state = REQ_READ,.on_arrival = requestReadInit,.on_read_ready = requestRead},
    {.state = ADDR_RESOLVE, .on_arrival = addressResolveInit, .on_write_ready = addressResolveDone,.on_block_ready = addressResolveDone}, //todo cambiar nombre!?
    {.state = CONNECTING, .on_arrival = NULL, .on_write_ready = requestConnecting},
    {.state = REQ_WRITE, .on_write_ready = requestWrite},
    {.state = COPYING,   .on_arrival = socksv5HandleInit,.on_read_ready = socksv5HandleRead,.on_write_ready = socksv5HandleWrite,.on_departure = socksv5HandleClose},
    {.state = CLOSED, .on_arrival = closeArrival},
    {.state=ERROR, .on_arrival = errorArrival}
};
void socksv5PassiveAccept(struct selector_key* key){
    struct sockaddr_storage clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    int newClientSocket = accept(key->fd, (struct sockaddr*)&clientAddress, &clientAddressLen);
    if (newClientSocket < 0) {
        perror("Error accepting new client connection");
        return;
    }
    if (newClientSocket >= FD_SETSIZE) {
        LOG_ERROR("%s" ,"New client socket exceeds maximum file descriptor limit");
        close(newClientSocket);
        return;
    }
    ClientData * clientData = calloc(1,sizeof(struct ClientData));
    if (clientData == NULL) {
        perror("Error allocating memory for client data");
        close(newClientSocket);
        return;
    }
    LOG_DEBUG("New client connected on socket %d", newClientSocket);
    stats_connection_opened();
    clientData->stm.initial = NEGOTIATION_READ;
    clientData->stm.max_state = ERROR;
    clientData->closed = false;
    clientData->stm.states = clientActions;
    clientData->clientFd = newClientSocket;
    clientData->clientAddress = clientAddress;
    clientData->originFd = -1;
    clientData->originResolution = NULL;
    clientData->resolution_from_getaddrinfo = false;
    clientData->connection_ready = 0;
    clientData->dns_resolution_state = 0;
    clientData->unregistering_origin = false;
    
    // Inicializar campos de logging
    clientData->user = NULL;
    memset(clientData->client_ip, 0, sizeof(clientData->client_ip));
    memset(clientData->target_host, 0, sizeof(clientData->target_host));
    clientData->client_port = 0;
    clientData->target_port = 0;
    clientData->socks_status = 0;
    
    // Extraer IP y puerto del cliente
    if (clientAddress.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&clientAddress;
        inet_ntop(AF_INET, &addr_in->sin_addr, clientData->client_ip, INET6_ADDRSTRLEN);
        clientData->client_port = ntohs(addr_in->sin_port);
    } else if (clientAddress.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&clientAddress;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, clientData->client_ip, INET6_ADDRSTRLEN);
        clientData->client_port = ntohs(addr_in6->sin6_port);
    }
    // Asignar buffers dinámicos con el tamaño actual
    clientData->bufferSize = get_current_buffer_size();
    clientData->inClientBuffer = malloc(clientData->bufferSize);
    clientData->inOriginBuffer = malloc(clientData->bufferSize);
    
    if (clientData->inClientBuffer == NULL || clientData->inOriginBuffer == NULL) {
        LOG_ERROR("Failed to allocate dynamic buffers for client");
        if (clientData->inClientBuffer) free(clientData->inClientBuffer);
        if (clientData->inOriginBuffer) free(clientData->inOriginBuffer);
        free(clientData);
        close(newClientSocket);
        return;
    }
    
    buffer_init(&clientData->clientBuffer, clientData->bufferSize, clientData->inClientBuffer);
    buffer_init(&clientData->originBuffer, clientData->bufferSize, clientData->inOriginBuffer);

    stm_init(&clientData->stm);
    selector_status ss = selector_register(key->s, newClientSocket, &handler, OP_READ, clientData);
    if (ss != SELECTOR_SUCCESS) {
        free(clientData->inClientBuffer);
        free(clientData->inOriginBuffer);
        free(clientData);
        close(newClientSocket);
        return;
    }
    if(selector_fd_set_nio(newClientSocket) == -1) { //todo check si esta bien
        LOG_ERROR("Failed to set non-blocking mode for new client socket %d", newClientSocket);
        free(clientData->inClientBuffer);
        free(clientData->inOriginBuffer);
        free(clientData);
        close(newClientSocket);
        return;
    }

}
static void socksv5Read(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    LOG_DEBUG("SOCKS5_READ: Reading data from socket %d", key->fd);

    const enum socks5State state = stm_handler_read(&clientData->stm, key);
    if (state == ERROR || state == CLOSED) {
        closeConnection(key);
        return;
    }
}
static void socksv5Write(struct selector_key *key) {
    if (key == NULL) {
        LOG_ERROR("%s" ,"socksv5Write: key is NULL");
        return;
    }
    if (key->data == NULL) {
        LOG_ERROR("%s" ,"socksv5Write: key->data is NULL");
        return;
    }
    ClientData *clientData = (ClientData *)key->data;
    const enum socks5State state = stm_handler_write(&clientData->stm, key);
    LOG_DEBUG("socksv5Write: stm_handler_write returned: %d", state);
    if (state == ERROR || state == CLOSED) {
        closeConnection(key);
        return;
    }
}
static void socksv5Close(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    if (clientData->unregistering_origin) {
        return;
    }

    stm_handler_close(&clientData->stm, key);
    closeConnection(key);
}
static void socksv5Block(struct selector_key *key) {
    if (key == NULL) {
        LOG_ERROR("%s" ,"socksv5Block: key is NULL");
        return;
    }
    if (key->data == NULL) {
        LOG_ERROR("%s" ,"socksv5Block: key->data is NULL");
        return;
    }
    ClientData *clientData = (ClientData *)key->data;
    const enum socks5State state = stm_handler_block(&clientData->stm, key);
    LOG_DEBUG("socksv5Block: stm_handler_block returned: %d", state);
    if (state == ERROR || state == CLOSED) {
        closeConnection(key);
        return;
    }
}
void closeConnection(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    if (clientData->closed) {
        return; // ya fue cerrado
    }
    stats_connection_closed();
    clientData->closed = true;
    if (killed) {

        if (clientData->originFd >= 0 && clientData->originFd != key->fd) {
            selector_unregister_fd(key->s, clientData->originFd);
            close(clientData->originFd);
        }
        if (clientData->clientFd >= 0 && clientData->clientFd != key->fd) {
            selector_unregister_fd(key->s, clientData->clientFd);
            close(clientData->clientFd);
        }
    } else {

        if (clientData->originFd >= 0) {
            selector_unregister_fd(key->s, clientData->originFd);
            close(clientData->originFd);
        }
        if (clientData->clientFd >= 0) {
            selector_unregister_fd(key->s, clientData->clientFd);
            close(clientData->clientFd);
        }
    }

    if (clientData->dns_resolution_state == 1) {
        // Cancelar resolución pendiente
        struct gaicb *reqs[] = { &clientData->dns_req.req };
        gai_cancel(reqs[0]);
    }

    // Cleanup DNS resolution memory
    if (clientData->originResolution != NULL) {
        if (clientData->resolution_from_getaddrinfo) {
            // Memoria de getaddrinfo_a() - usar freeaddrinfo
            freeaddrinfo(clientData->originResolution);
        } else {
            // Memoria manual - liberar ai_addr y estructura por separado
            if (clientData->originResolution->ai_addr != NULL) {
                free(clientData->originResolution->ai_addr);
            }
            free(clientData->originResolution);
        }
    }

    // Registro de acceso antes de liberar clientData
    log_access_record(clientData);

    // Liberar buffers dinámicos
    if (clientData->inClientBuffer != NULL) {
        free(clientData->inClientBuffer);
    }
    if (clientData->inOriginBuffer != NULL) {
        free(clientData->inOriginBuffer);
    }

    free(clientData);
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



void log_access_record(ClientData *clientData) {
    if (!clientData) return;
    
    // Fecha en formato ISO-8601
    time_t now = time(NULL);
    struct tm *utc_tm = gmtime(&now);
    char timestamp[TIMESTAMP_BUFFER_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", utc_tm);
    
    // REGISTRO DE ACCESO: fecha\tusuario\tA\tip_origen\tpuerto_origen\tdestino\tpuerto_destino\tstatus

    LOG_INFO("%-25s  %-12s  %-2s  %-17s  %-6d  %-25s  %-6d  %-2d",
             timestamp,
             clientData->user ? clientData->user->name : "anonymous",
             "A",
             clientData->client_ip[0] ? clientData->client_ip : "unknown",
             clientData->client_port,
             clientData->target_host[0] ? clientData->target_host : "unknown",
             clientData->target_port,
             clientData->socks_status);


    log_store_for_user(clientData);

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

fd_handler * getSocksv5Handler(void) {
    return &handler;
}


//@TODO tiene sentido esto?
static void closeArrival(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("Arriving at CLOSED state (state = %d, key = %p)", state, (void *)key);
}

static void errorArrival(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("Arriving at ERROR state (state = %d, key = %p)", state, (void *)key);
}