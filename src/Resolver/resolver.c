#define _GNU_SOURCE
#include <netdb.h>
#include <signal.h>
#include "resolver.h"
#include "../selector.h"
#include "../stm.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

// Declaraciones externas
extern void closeConnection(struct selector_key *key);
extern unsigned stm_handler_read(struct state_machine *stm, struct selector_key *key);
extern unsigned stm_handler_write(struct state_machine *stm, struct selector_key *key);
extern unsigned stm_handler_block(struct state_machine *stm, struct selector_key *key);
extern void stm_handler_close(struct state_machine *stm, struct selector_key *key);

// Funciones para registrar sockets en el selector
void dnsResolutionDone(union sigval sv);




// Funciones para la máquina de estados

void requestReadInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    initResolverParser(&clientData->client.reqParser);
    printf("[DEBUG] REQ_READ_INIT: Iniciando lectura de request SOCKS5\n");
}

unsigned requestRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Leer del socket al buffer
    size_t writeLimit;
    uint8_t *b = buffer_write_ptr(&clientData->clientBuffer, &writeLimit);
    ssize_t readCount = recv(key->fd, b, writeLimit, 0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    buffer_write_adv(&clientData->clientBuffer, readCount);

    // Print del buffer antes de parsear
    printf("[DEBUG] REQ_READ: Bytes en el buffer antes de parsear: ");
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(&clientData->clientBuffer, &nbytes);
    for (size_t i = 0; i < nbytes; i++) {
        printf("%02x ", ptr[i]);
    }
    printf("\n");

    printf("[DEBUG] REQ_READ: Parseando request...\n");
    request_parse result = resolverParse(parser, &clientData->clientBuffer);

    switch (result) {
        case REQUEST_PARSE_INCOMPLETE:
            printf("[DEBUG] REQ_READ: Parse incompleto, esperando más datos\n");
            return REQ_READ;

        case REQUEST_PARSE_OK:
            printf("[DEBUG] REQ_READ: Request parseado exitosamente:\n");
            printf("  Command: %d\n", parser->command);
            printf("  Address Type: %d\n", parser->address_type);
            printf("  Port: %d\n", htons(parser->port));

            if (parser->address_type == ATYP_DOMAIN) {
                printf("  Domain: %.*s\n", parser->domain_length, parser->domain);
            } else if (parser->address_type == ATYP_IPV4) {
                printf("  IPv4: %d.%d.%d.%d\n",
                    parser->ipv4_addr[0], parser->ipv4_addr[1],
                    parser->ipv4_addr[2], parser->ipv4_addr[3]);
            }

            // Por ahora solo soportamos CONNECT
            if (parser->command != CMD_CONNECT) {
                printf("[DEBUG] REQ_READ: Comando no soportado (%d), enviando error\n", parser->command);
                // Enviar error: Command not supported
                sendRequestResponse(&clientData->originBuffer, 0x05, 0x07, ATYP_IPV4, parser->ipv4_addr, 0);
                return REQ_WRITE;
            }

            printf("[DEBUG] REQ_READ: Avanzando a ADDR_RESOLVE\n");
            // Para CONNECT, necesitamos resolver la dirección
            return ADDR_RESOLVE;

        case REQUEST_PARSE_ERROR:
            printf("[DEBUG] REQ_READ: Error parsing request\n");
            // Enviar error: General SOCKS server failure
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
    }

    return ERROR;
}

unsigned requestWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] REQ_WRITE: Escribiendo respuesta al cliente\n");
    
    if (buffer_can_read(&clientData->originBuffer)) {
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
        // ssize_t bytes_written = write(clientData->clientFd, write_ptr, bytes_to_write);
        ssize_t bytes_written = send(clientData->clientFd, write_ptr, bytes_to_write, MSG_NOSIGNAL);
        // todo: cambie las lineas de arriba, revisen porfa. mati
        
        if (bytes_written < 0) {
            printf("[DEBUG] REQ_WRITE: Error escribiendo al cliente\n");
            return ERROR;
        }
        
        buffer_read_adv(&clientData->originBuffer, bytes_written);
        
        if (buffer_can_read(&clientData->originBuffer)) {
            printf("[DEBUG] REQ_WRITE: Más datos para escribir\n");
            return REQ_WRITE;
        }
    }
    
    printf("[DEBUG] REQ_WRITE: Respuesta enviada, cerrando conexión\n");
    return CLOSED;
}

// Funciones para el estado ADDR_RESOLVE
void addressResolveInit(const unsigned state, struct selector_key *key) {
    printf("[DEBUG] ADDR_RESOLVE_INIT: Iniciando resolución de dirección\n");

    // Ejecutar la resolución inmediatamente
    unsigned next = addressResolveDone(key);
    printf("[DEBUG] ADDR_RESOLVE_INIT: addressResolveDone retornó: %d\n", next);

    if (next == CONNECTING || next == ADDR_RESOLVE) {
        if(selector_set_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
            printf("[ERROR] ADDR_RESOLVE_INIT: Error activando eventos para transición\n");
            closeConnection(key);
            return;
        }
    } else if (next == ADDR_RESOLVE) {
        // Para dominios DNS - desactivar eventos hasta que termine resolución
        if(selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
            printf("[ERROR] ADDR_RESOLVE_INIT: Error desactivando eventos\n");
            closeConnection(key);
            return;
        }

    }
}

unsigned addressResolveDone(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    printf("[DEBUG] ADDR_RESOLVE: Iniciando resolución de dirección\n");
    if (clientData->dns_resolution_state == 2){
        clientData->dns_resolution_state = 0;
        return CONNECTING;
    }else if (clientData->dns_resolution_state == 1) {
        printf("[DEBUG] ADDR_RESOLVE: Resolución de DNS ya en progreso, esperando\n");
        return ADDR_RESOLVE; // Esperar a que se complete la resolución
    }else if (clientData->dns_resolution_state == -1){
        printf("[DEBUG] ADDR_RESOLVE: Resolución de DNS fallida, enviando error\n");
        sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
        return REQ_WRITE; // Enviar error y cerrar conexión
    }
    // Limpiar resolución previa si existe
    if (clientData->originResolution != NULL) {
        if (clientData->originResolution->ai_addr != NULL) {
            free(clientData->originResolution->ai_addr);
        }
        free(clientData->originResolution);
        clientData->originResolution = NULL;
    }
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", ntohs(parser->port));
    int gai_ret = 0;
    if (parser->address_type == ATYP_IPV4) {
         printf("[DEBUG] ADDR_RESOLVE: Resolviendo IPv4 directa\n");
          struct sockaddr_in* ipv4_addr = malloc(sizeof(struct sockaddr_in));
            if (ipv4_addr == NULL) {
            printf("[DEBUG] ADDR_RESOLVE: Error al asignar memoria para resolución IPv4\n");
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
            }
          clientData->originResolution = calloc(1, sizeof(struct addrinfo));
          if(clientData->originResolution == NULL) {
                printf("[DEBUG] ADDR_RESOLVE: Error al asignar memoria para resolución IPv4\n");
                sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
                return REQ_WRITE;
          }
          *ipv4_addr = (struct sockaddr_in){
                .sin_family = AF_INET,
                .sin_port =htons(parser->port),
                .sin_addr = *(struct in_addr *)parser->ipv4_addr
          };
          *clientData->originResolution = (struct addrinfo){
                .ai_family = AF_INET,
                .ai_addrlen = sizeof(*ipv4_addr),
                .ai_addr = (struct sockaddr *)ipv4_addr,
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = IPPROTO_TCP
          };

          return CONNECTING;
    } else if (parser->address_type == ATYP_IPV6) {
        printf("[DEBUG] ADDR_RESOLVE: Resolviendo IPv6 directa\n");
        struct sockaddr_in6* ipv6_addr = malloc(sizeof(struct sockaddr_in6));
        if (ipv6_addr == NULL) {
            printf("[DEBUG] ADDR_RESOLVE: Error al asignar memoria para resolución IPv6\n");
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }
        clientData->originResolution = calloc(1,sizeof(struct addrinfo));
        if(clientData->originResolution == NULL ) {
            printf("[DEBUG] ADDR_RESOLVE: Error al asignar memoria para resolución IPv6\n");
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }
        *ipv6_addr = (struct sockaddr_in6){
                .sin6_family = AF_INET6,
                .sin6_port = htons(parser->port),
        };
        memcpy(&ipv6_addr->sin6_addr, parser->ipv6_addr, 16);
        *clientData->originResolution= (struct addrinfo){
            .ai_family = AF_INET6,
            .ai_addrlen = sizeof(*ipv6_addr),
            .ai_addr = (struct sockaddr *)ipv6_addr,
                    .ai_socktype = SOCK_STREAM,
                    .ai_protocol = IPPROTO_TCP
        };
        return CONNECTING;

    } else if (parser->address_type == ATYP_DOMAIN) {
        struct dns_request * dns_req = &clientData->dns_req;
        snprintf(dns_req->port, sizeof(dns_req->port), "%u", parser->port);
        memset(&dns_req->hints, 0, sizeof(dns_req->hints));
        struct gaicb *reqs[] = { &dns_req->req };
        dns_req->hints.ai_family = AF_UNSPEC;
        dns_req->hints.ai_socktype = SOCK_STREAM;
        dns_req->hints.ai_protocol = IPPROTO_TCP;
        dns_req->req.ar_name = parser->domain;
        dns_req->req.ar_service = dns_req->port;
        dns_req->req.ar_request = &dns_req->hints;
        dns_req->req.ar_result = NULL;
        dns_req->clientData = clientData;
        dns_req->selector = key->s;
        dns_req->fd = key->fd;
        struct sigevent sev = {0};
        sev.sigev_notify = SIGEV_THREAD;
        sev.sigev_notify_function = dnsResolutionDone;
        sev.sigev_value.sival_ptr = dns_req;  // paso dns_req al callback

        if (getaddrinfo_a(GAI_NOWAIT, reqs, 1, &sev) != 0) {
            printf("[DEBUG] ADDR_RESOLVE: Error iniciando resolución de dominio: %s\n", gai_strerror(gai_ret));
            // Enviar error: General SOCKS server failure
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }
        clientData->dns_resolution_state = 1; // Indica que la resolución está en progreso

        return ADDR_RESOLVE;
    }

    if (gai_ret != 0 || clientData->originResolution == NULL) {
        printf("[DEBUG] ADDR_RESOLVE: Error resolviendo dirección: %s\n", gai_strerror(gai_ret));
        // Error en la resolución
        sendRequestResponse(&clientData->originBuffer, 0x05, 0x04, ATYP_IPV4, parser->ipv4_addr, 0);
        return REQ_WRITE;
    }

    printf("[DEBUG] ADDR_RESOLVE: Dirección resuelta exitosamente, avanzando a CONNECTING\n");

    // Retornar CONNECTING para que la máquina de estados avance
    return CONNECTING;
}

void requestConnectingInit(const unsigned state, struct selector_key *key) {
    printf("[DEBUG] CONNECTING_INIT: Entrando a requestConnectingInit\n");
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    printf("[DEBUG] CONNECTING_INIT: Iniciando conexión al destino\n");

    // Crear socket para conectar al destino
    struct addrinfo *ai = clientData->originResolution;
    clientData->originFd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (clientData->originFd < 0) {
        printf("[DEBUG] CONNECTING_INIT: Error creando socket: %s\n", strerror(errno));
        sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
        return;
    }
    if(selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        printf("[ERROR] Error desactivando eventos del cliente\n");
        return;
    }
    // IMPORTANTE: Hacer el socket no bloqueante
    selector_fd_set_nio(clientData->originFd);
    printf("[DEBUG] CONNECTING_INIT: Socket creado (fd=%d), intentando conectar\n", clientData->originFd);

    // Intentar conectar
    int connect_result = connect(clientData->originFd, ai->ai_addr, ai->ai_addrlen);

    if (connect_result == 0) {
        // Conexión inmediata (poco común pero posible)
        printf("[DEBUG] CONNECTING_INIT: Conexión completada inmediatamente\n");
        // Registrar para poder manejar el estado exitoso
        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            printf("[ERROR] CONNECTING_INIT: Error registrando socket de origen\n");
            close(clientData->originFd);
            clientData->originFd = -1;
            return;
        }
        // Marcar que la conexión está lista
        selector_set_interest(key->s, key->fd, OP_WRITE);
        clientData->connection_ready = 1;

    } else if (errno == EINPROGRESS) {
        // Conexión en progreso - esto es lo normal
        printf("[DEBUG] CONNECTING_INIT: Conexión en progreso (EINPROGRESS)\n");

        // Registrar el socket para detectar cuando esté listo para escritura
        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            printf("[ERROR] CONNECTING_INIT: Error registrando socket de origen\n");
            close(clientData->originFd);
            clientData->originFd = -1;
            return;
        }
        // La conexión aún no está lista
        clientData->connection_ready = 0;

    } else {
        // Error inmediato en connect()
        printf("[DEBUG] CONNECTING_INIT: Error conectando: %s\n", strerror(errno));
        close(clientData->originFd);

        // Intentar siguiente dirección si existe
        if (clientData->originResolution->ai_next != NULL) {
            struct addrinfo* next = clientData->originResolution->ai_next;
            freeaddrinfo(clientData->originResolution);
            clientData->originResolution = next;
            requestConnectingInit(state, key);
            return;
        }
        clientData->originFd = -1;
        sendRequestResponse(&clientData->originBuffer, 0x05, 0x05, ATYP_IPV4, parser->ipv4_addr, 0);
        return;
    }

    // No configurar el cliente para escritura todavía - esperamos que la conexión termine
    printf("[DEBUG] CONNECTING_INIT: Esperando completar conexión...\n");
}

unsigned requestConnecting(struct selector_key *key) {
    printf("[DEBUG] requestConnecting: Verificando estado de conexión\n");

    if (key == NULL || key->data == NULL) {
        printf("[ERROR] requestConnecting: key o key->data es NULL\n");
        return ERROR;
    }

    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Si la conexión ya estaba marcada como lista, proceder
    if (clientData->connection_ready) {
        printf("[DEBUG] requestConnecting: Conexión ya estaba lista\n");
    } else {
        // Verificar si la conexión se completó exitosamente
        int so_error = 0;
        socklen_t len = sizeof(so_error);

        if (getsockopt(clientData->originFd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
            printf("[ERROR] requestConnecting: Error en getsockopt: %s\n", strerror(errno));
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }
        printf("[DEBUG] requestConnecting: getsockopt SO_ERROR = %d (%s)\n", so_error, strerror(so_error));

        if (so_error != 0) {
            printf("[DEBUG] requestConnecting: Error en conexión: %s\n", strerror(so_error));
            close(clientData->originFd);

            // Intentar siguiente dirección si existe
            if (clientData->originResolution->ai_next != NULL) {
                struct addrinfo* next = clientData->originResolution->ai_next;
                freeaddrinfo(clientData->originResolution);
                clientData->originResolution = next;
                // Volver a intentar conexión
                requestConnectingInit(CONNECTING, key);
                return CONNECTING;
            }

            clientData->originFd = -1;
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x05, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }

        printf("[DEBUG] requestConnecting: Conexión exitosa\n");
        clientData->connection_ready = 1;
    }

    // Obtener la dirección local del socket para la respuesta
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(clientData->originFd, (struct sockaddr*)&local_addr, &local_addr_len) < 0) {
        printf("[DEBUG] requestConnecting: Error obteniendo dirección local\n");
        memset(parser->ipv4_addr, 0, 4);
    } else {
        if (local_addr.ss_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in*)&local_addr;
            memcpy(parser->ipv4_addr, &addr_in->sin_addr, 4);
        } else if (local_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&local_addr;
            memcpy(parser->ipv6_addr, &addr_in6->sin6_addr, 16);
        }
    }

    // Preparar respuesta de éxito
    printf("[DEBUG] requestConnecting: Preparando respuesta de éxito\n");
    sendRequestResponse(&clientData->originBuffer, 0x05, 0x00, ATYP_IPV4, parser->ipv4_addr, 0);

    // Configurar cliente para escribir la respuesta
    if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE) != SELECTOR_SUCCESS) {
        printf("[ERROR] requestConnecting: Error configurando cliente para escritura\n");
        return ERROR;
    }

    // Escribir respuesta inmediatamente si es posible
    if (buffer_can_read(&clientData->originBuffer)) {
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_written = send(clientData->clientFd, write_ptr, bytes_to_write, MSG_NOSIGNAL);

        if (bytes_written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // El socket no está listo, el selector nos llamará cuando lo esté
                printf("[DEBUG] requestConnecting: Socket no listo, esperando\n");
                return CONNECTING;
            }
            printf("[DEBUG] requestConnecting: Error escribiendo respuesta: %s\n", strerror(errno));
            return ERROR;
        }

        buffer_read_adv(&clientData->originBuffer, bytes_written);

        if (buffer_can_read(&clientData->originBuffer)) {
            printf("[DEBUG] requestConnecting: Respuesta parcial enviada, esperando completar\n");
            return CONNECTING;
        }
    }

    printf("[DEBUG] requestConnecting: Respuesta enviada completamente, avanzando a COPYING\n");
    return COPYING;
}



void dnsResolutionDone(union sigval sv) {
    struct dns_request *dns_req = sv.sival_ptr;
    ClientData *clientData = (ClientData *)dns_req->clientData;
    int ret = gai_error(&dns_req->req);
    if (ret != 0) {
        printf("[DEBUG] Error en resolución: %s\n", gai_strerror(ret));
        freeaddrinfo(dns_req->req.ar_result);
        clientData->dns_resolution_state = -1;
        selector_notify_block(dns_req->selector,dns_req->fd);
        return;
    }
    clientData->originResolution = dns_req->req.ar_result;
    clientData->dns_resolution_state = 2; // Indica que la resolución se completó exitosamente
    selector_notify_block(dns_req->selector,dns_req->fd);
    printf("[DEBUG] Resolución exitosa, usando dirección...\n");
    }

