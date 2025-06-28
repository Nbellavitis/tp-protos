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
static void socksv5Read(struct selector_key *key);
static void socksv5Write(struct selector_key *key);
static void socksv5Close(struct selector_key *key);
static void socksv5Block(struct selector_key *key);
void dnsResolutionDone(union sigval sv);
static fd_handler handler = {
     .handle_read = socksv5Read,
     .handle_write = socksv5Write,
     .handle_close = socksv5Close,
     .handle_block = socksv5Block,
};



// Funciones para la máquina de estados

void requestReadInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    initResolverParser(&clientData->client.reqParser);
    printf("[DEBUG] REQ_READ_INIT: Iniciando lectura de request SOCKS5\n");
}

unsigned requestRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Verificar si la conexión fue cerrada
    if (clientData->closed) {
        return CLOSED;
    }

    // Leer del socket al buffer
    size_t writeLimit;
    uint8_t *b = buffer_write_ptr(&clientData->clientBuffer, &writeLimit);
    ssize_t readCount = recv(key->fd, b, writeLimit, 0);
    if (readCount <= 0) {
        return (readCount == 0) ? CLOSED : ERROR;
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
            printf("  Port: %d\n", parser->port);

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
    
    // Verificar si la conexión fue cerrada
    if (clientData->closed) {
        return CLOSED;
    }
    
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
        
        if (bytes_written == 0) {
            return CLOSED;
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

    // Si la resolución fue exitosa, configurar el selector para escritura
    if (next == CONNECTING) {
        printf("[DEBUG] ADDR_RESOLVE_INIT: Configurando selector para escritura\n");
        if(selector_set_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
            printf("[ERROR] ADDR_RESOLVE_INIT: Error configurando selector para escritura\n");
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
        freeaddrinfo(clientData->originResolution);
        clientData->originResolution = NULL;
    }

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", parser->port);



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
                .sin_port = htons(parser->port),
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
        ipv6_addr->sin6_family = AF_INET6;
        ipv6_addr->sin6_port = htons(parser->port);
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
        struct gaicb *reqs[] = { &dns_req->req };
        
        // Configurar hints en el buffer persistente
        memset(&dns_req->hints, 0, sizeof(dns_req->hints));
        dns_req->hints.ai_family = AF_UNSPEC;      // Soporta IPv4 o IPv6
        dns_req->hints.ai_socktype = SOCK_STREAM;  // TCP
        dns_req->hints.ai_protocol = IPPROTO_TCP;  // TCP
        
        // Crear strings null-terminated en los buffers persistentes
        memcpy(dns_req->domain_str, parser->domain, parser->domain_length);
        dns_req->domain_str[parser->domain_length] = '\0';
        strcpy(dns_req->port_str, port_str);
        
        dns_req->req.ar_name = dns_req->domain_str;
        dns_req->req.ar_service = dns_req->port_str;
        dns_req->req.ar_request = &dns_req->hints;
        dns_req->req.ar_result = NULL;
        dns_req->clientData = clientData;
        dns_req->selector = key->s;
        dns_req->fd = key->fd;
        struct sigevent sev = {0};
        sev.sigev_notify = SIGEV_THREAD;
        sev.sigev_notify_function = dnsResolutionDone;
        sev.sigev_value.sival_ptr = dns_req;  // paso dns_req al callback

        int gai_result = getaddrinfo_a(GAI_NOWAIT, reqs, 1, &sev);
        if (gai_result != 0) {
            printf("[DEBUG] ADDR_RESOLVE: Error iniciando resolución de dominio: %s\n", gai_strerror(gai_result));
            // Enviar error: General SOCKS server failure
            sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
            return REQ_WRITE;
        }
        clientData->dns_resolution_state = 1; // Indica que la resolución está en progreso
        printf("[DEBUG] ADDR_RESOLVE: Resolución DNS iniciada para dominio: %s\n", dns_req->domain_str);

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
    selector_fd_set_nio(clientData->originFd);
    printf("[DEBUG] CONNECTING_INIT: Socket creado (fd=%d), intentando conectar\n", clientData->originFd);

    // Intentar conectar
    if (connect(clientData->originFd, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS) {
        printf("[DEBUG] CONNECTING_INIT: Error conectando: %s\n", strerror(errno));
        close(clientData->originFd);
        if (clientData->originResolution->ai_next != NULL) {
            struct addrinfo* next = clientData->originResolution->ai_next;
            freeaddrinfo(clientData->originResolution);
            clientData->originResolution = next;
            requestConnectingInit(state, key);
            return;
        }
        clientData->originFd = -1; // Resetear fd en caso de error
        sendRequestResponse(&clientData->originBuffer, 0x05, 0x05, ATYP_IPV4, parser->ipv4_addr, 0);
        return;
    }

    printf("[DEBUG] CONNECTING_INIT: Conexión exitosa al destino\n");

    // Obtener la dirección local del socket para la respuesta
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(clientData->originFd, (struct sockaddr*)&local_addr, &local_addr_len) < 0) {
        printf("[DEBUG] CONNECTING_INIT: Error obteniendo dirección local\n");
        // Usar dirección por defecto
        memset(parser->ipv4_addr, 0, 4);
    } else {
        // Extraer la dirección local según el tipo
        if (local_addr.ss_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in*)&local_addr;
            memcpy(parser->ipv4_addr, &addr_in->sin_addr, 4);
        } else if (local_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&local_addr;
            // Para IPv6, usar los primeros 4 bytes o convertir
            memcpy(parser->ipv4_addr, &addr_in6->sin6_addr, 4);
        }
    }

    // Conexión exitosa - enviar respuesta con éxito
    printf("[DEBUG] CONNECTING_INIT: Enviando respuesta de éxito al cliente\n");
    sendRequestResponse(&clientData->originBuffer, 0x05, 0x00, ATYP_IPV4, parser->ipv4_addr, 0);

    // Configurar el selector para escribir la respuesta al cliente
    printf("[DEBUG] CONNECTING_INIT: Configurando selector para escritura en cliente (fd=%d)\n", clientData->clientFd);
    if (selector_register(key->s, clientData->originFd, &handler, OP_WRITE, clientData)){
        printf("[ERROR] CONNECTING_INIT: Error registrando socket de origen en selector\n");
        close(clientData->originFd);
        clientData->originFd = -1; // Resetear fd en caso de error
        return;
    }
    if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE) != SELECTOR_SUCCESS) {
        printf("[ERROR] CONNECTING_INIT: Error configurando selector para escritura en cliente\n");
        close(clientData->originFd);
        clientData->originFd = -1; // Resetear fd en caso de error
        return;
    }

    printf("[DEBUG] CONNECTING_INIT: Finalizado, esperando que el selector llame a requestConnecting\n");
    printf("[DEBUG] CONNECTING_INIT: Estado actual de la máquina: %d\n", stm_state(&clientData->stm));
}

unsigned requestConnecting(struct selector_key *key) {
    printf("[DEBUG] requestConnecting: Entrando a requestConnecting\n");
    if (key == NULL) {
        printf("[ERROR] requestConnecting: key es NULL\n");
        return ERROR;
    }
    if (key->data == NULL) {
        printf("[ERROR] requestConnecting: key->data es NULL\n");
        return ERROR;
    }
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] CONNECTING: Escribiendo respuesta de éxito al cliente\n");
    
    if (buffer_can_read(&clientData->originBuffer)) {
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_written = send(clientData->clientFd, write_ptr, bytes_to_write, MSG_NOSIGNAL);
        
        if (bytes_written < 0) {
            printf("[DEBUG] CONNECTING: Error escribiendo respuesta\n");
            return ERROR;
        }
        
        buffer_read_adv(&clientData->originBuffer, bytes_written);
        
        if (buffer_can_read(&clientData->originBuffer)) {
            printf("[DEBUG] CONNECTING: Más datos de respuesta para escribir\n");
            return CONNECTING;
        }
    }
    
    printf("[DEBUG] CONNECTING: Respuesta enviada, avanzando a COPYING\n");
    // Si no hay más datos para escribir, pasar al estado COPYING
    return COPYING;
}

// Funciones para el estado COPYING (manejo de datos entre cliente y servidor)
void socksv5HandleInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("Iniciando copia de datos entre cliente y servidor\n");
    
    // Registrar el socket del servidor de origen en el selector
    printf("[DEBUG] COPYING_INIT: Registrando socket del servidor de origen (fd=%d) en el selector\n", clientData->originFd);

    // Registrar el socket del cliente para lectura
    printf("[DEBUG] COPYING_INIT: Configurando socket del cliente (fd=%d) para lectura\n", clientData->clientFd);
    if(selector_set_interest(key->s, clientData->clientFd, OP_READ) != SELECTOR_SUCCESS) {
        printf("[ERROR] COPYING_INIT: Error configurando selector para lectura en el cliente\n");
        closeConnection(key);
        return;
    }
}

unsigned socksv5HandleRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] COPYING_READ: Leyendo datos del socket %d\n", key->fd);
    
    // Leer datos del socket activo y escribirlos en el buffer correspondiente
    if (key->fd == clientData->clientFd) {
        // Datos del cliente -> servidor de origen
        printf("[DEBUG] COPYING_READ: Leyendo datos del cliente\n");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(key->fd, write_ptr, bytes_to_write, 0);
        
        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Cliente cerró conexión\n");
            return CLOSED;
        }
        
        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del cliente\n", bytes_read);
        buffer_write_adv(&clientData->originBuffer, bytes_read);
        
        // Cambiar a escritura en el socket de origen
        printf("[DEBUG] COPYING_READ: Configurando socket del servidor para escritura\n");
        if(selector_set_interest(key->s, clientData->originFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            printf("[ERROR] COPYING_READ: Error configurando selector para escritura en el origen\n");
            return ERROR;
        }
        return COPYING;
        
    } else if (key->fd == clientData->originFd) {
        // Datos del servidor de origen -> cliente
        printf("[DEBUG] COPYING_READ: Leyendo datos del servidor\n");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->clientBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(clientData->originFd, write_ptr, bytes_to_write, 0);
        
        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Servidor cerró conexión\n");
            return CLOSED;
        }
        
        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del servidor\n", bytes_read);
        buffer_write_adv(&clientData->clientBuffer, bytes_read);
        
        // Cambiar a escritura en el socket del cliente
        printf("[DEBUG] COPYING_READ: Configurando socket del cliente para escritura\n");
        if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            printf("[ERROR] COPYING_READ: Error configurando selector para escritura en el cliente\n");
            return ERROR;
        }
        return COPYING;
    }
    
    printf("[ERROR] COPYING_READ: Socket desconocido: %d\n", key->fd);
    return ERROR;
}

unsigned socksv5HandleWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    
    // Escribir datos del buffer al socket correspondiente
    if (key->fd == clientData->clientFd) {
        // Escribir datos del buffer del cliente al cliente
        if (buffer_can_read(&clientData->clientBuffer)) {
            size_t bytes_to_write;
            uint8_t *read_ptr = buffer_read_ptr(&clientData->clientBuffer, &bytes_to_write);
            ssize_t bytes_written = send(clientData->clientFd, read_ptr, bytes_to_write, MSG_NOSIGNAL);
            
            if (bytes_written < 0) {
                return ERROR;
            }
            
            buffer_read_adv(&clientData->clientBuffer, bytes_written);
            
            if (buffer_can_read(&clientData->clientBuffer)) {
                return COPYING;
            }
        }
        
        // Cambiar a lectura en el socket del cliente
        if(selector_set_interest(key->s, clientData->clientFd, OP_READ)){
            printf("[ERROR] socksv5HandleWrite: Error configurando selector para lectura en el cliente\n");
            return ERROR;
        }
        return COPYING;
        
    } else if (key->fd == clientData->originFd) {
        // Escribir datos del buffer del origen al servidor de origen
        if (buffer_can_read(&clientData->originBuffer)) {
            size_t bytes_to_write;
            uint8_t *read_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
            ssize_t bytes_written = send(clientData->originFd, read_ptr, bytes_to_write, MSG_NOSIGNAL);
            
            if (bytes_written < 0) {
                return ERROR;
            }
            
            buffer_read_adv(&clientData->originBuffer, bytes_written);
            
            if (buffer_can_read(&clientData->originBuffer)) {
                return COPYING;
            }
        }
        
        // Cambiar a lectura en el socket del servidor de origen
        if(selector_set_interest(key->s, clientData->originFd, OP_READ) != SELECTOR_SUCCESS) {
            printf("[ERROR] socksv5HandleWrite: Error configurando selector para lectura en el origen\n");
            return ERROR;
        }
        return COPYING;
    }
    
    return ERROR;
}

void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("Cerrando manejo de datos\n");
}

// Funciones para los estados finales
void closeArrival(const unsigned state, struct selector_key *key) {
    printf("Llegando al estado CLOSED\n");
    closeConnection(key);
}

void errorArrival(const unsigned state, struct selector_key *key) {
    printf("Llegando al estado ERROR\n");
    closeConnection(key);
}

// Implementaciones de las funciones del handler
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
void dnsResolutionDone(union sigval sv) {
    struct dns_request *dns_req = sv.sival_ptr;
    ClientData *clientData = (ClientData *)dns_req->clientData;
    
    // Verificar si la conexión fue cerrada/cancelada
    if (clientData->closed || clientData->dns_resolution_state == -2) {
        if (dns_req->req.ar_result != NULL) {
            freeaddrinfo(dns_req->req.ar_result);
        }
        if (clientData->dns_resolution_state == -2) {
            // Liberación diferida - ahora podemos liberar ClientData
            free(clientData);
        }
        return;
    }
    
    int ret = gai_error(&dns_req->req);
    if (ret != 0) {
        printf("[DEBUG] Error en resolución: %s\n", gai_strerror(ret));
        if (dns_req->req.ar_result != NULL) {
            freeaddrinfo(dns_req->req.ar_result);
        }
        clientData->dns_resolution_state = -1;
        selector_notify_block(dns_req->selector,dns_req->fd);
        return;
    }
    clientData->originResolution = dns_req->req.ar_result;
    clientData->dns_resolution_state = 2; // Indica que la resolución se completó exitosamente
    selector_notify_block(dns_req->selector,dns_req->fd);
    printf("[DEBUG] Resolución exitosa, usando dirección...\n");
    }

