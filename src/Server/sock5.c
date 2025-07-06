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
#include "Auth/authParser.h"
#include "Resolver/resolver.h"
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
    {.state = REQ_READ,.on_arrival = requestReadInit,.on_read_ready = requestRead},
    {.state = ADDR_RESOLVE, .on_arrival = addressResolveInit, .on_write_ready = addressResolveDone,.on_block_ready = addressResolveDone}, //todo cambiar nombre!?
    {.state = CONNECTING, .on_arrival = requestConnectingInit, .on_write_ready = requestConnecting},
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
        fprintf(stdout, "New client socket exceeds maximum file descriptor limit\n");
        close(newClientSocket);
        return;
    }
    ClientData * clientData = calloc(1,sizeof(struct ClientData));
    if (clientData == NULL) {
        perror("Error allocating memory for client data");
        close(newClientSocket);
        return;
    }
    printf("New client connected: %d\n", newClientSocket);
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
    clientData->connection_ready = 0; // No hay conexión pendiente
    clientData->dns_resolution_state = 0; // No hay resolución pendiente
    buffer_init(&clientData->clientBuffer, BUFFER_SIZE, clientData->inClientBuffer);
    buffer_init(&clientData->originBuffer, BUFFER_SIZE, clientData->inOriginBuffer);

    stm_init(&clientData->stm);
    selector_status ss = selector_register(key->s, newClientSocket, &handler, OP_READ, clientData);
    if (ss != SELECTOR_SUCCESS) {
        free(clientData);
        close(newClientSocket);
        return;
    }

}
static void socksv5Read(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    printf("[DEBUG] SOCKS5_READ: Leyendo datos del socket %d\n", key->fd);

    const enum socks5State state = stm_handler_read(&clientData->stm, key);
    if (state == ERROR || state == CLOSED) {
        closeConnection(key);
        return;
    }
}
static void socksv5Write(struct selector_key *key) {
    printf("[DEBUG] socksv5Write: Entrando a socksv5Write\n");
    if (key == NULL) {
        printf("[ERROR] socksv5Write: key es NULL\n");
        return;
    }
    if (key->data == NULL) {
        printf("[ERROR] socksv5Write: key->data es NULL\n");
        return;
    }
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] socksv5Write: Llamando a stm_handler_write\n");
    const enum socks5State state = stm_handler_write(&clientData->stm, key);
    printf("[DEBUG] socksv5Write: stm_handler_write retornó: %d\n", state);
    if (state == ERROR || state == CLOSED) {
        closeConnection(key);
        return;
    }
}
static void socksv5Close(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    stm_handler_close(&clientData->stm, key);
    closeConnection(key);
}
static void socksv5Block(struct selector_key *key) {
    printf("[DEBUG] socksv5Block: Entrando a socksv5Block\n");
    if (key == NULL) {
        printf("[ERROR] socksv5Block: key es NULL\n");
        return;
    }
    if (key->data == NULL) {
        printf("[ERROR] socksv5Block: key->data es NULL\n");
        return;
    }
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] socksv5Block: Llamando a stm_handler_block\n");
    const enum socks5State state = stm_handler_block(&clientData->stm, key);
    printf("[DEBUG] socksv5Block: stm_handler_block retornó: %d\n", state);
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

    if (clientData->originFd >= 0) {
        selector_unregister_fd(key->s, clientData->originFd);
        close(clientData->originFd);
    }
    if (clientData->clientFd >= 0) {
        selector_unregister_fd(key->s, clientData->clientFd);
        close(clientData->clientFd);
    }

    // Cancelar resolución DNS pendiente para evitar use-after-free
    //SEM_DOWN  // Proteger acceso a dns_resolution_state
    if (clientData->dns_resolution_state == 1) {
        // Cancelar resolución pendiente
        struct gaicb *reqs[] = { &clientData->dns_req.req };
        gai_cancel(reqs[0]);
    }
    //SEM_UP

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

    free(clientData);
}
fd_handler * getSocksv5Handler(void) {
    return &handler;
}



static void closeArrival(const unsigned state, struct selector_key *key) {
    printf("Llegando al estado CLOSED (state = %d, key = %p)\n", state, key);
}

static void errorArrival(const unsigned state, struct selector_key *key) {
    printf("Llegando al estado ERROR (state = %d, key = %p)\n", state, key);
}