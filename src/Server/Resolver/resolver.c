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
#include "../../logger.h"

// Declaraciones externas
extern void closeConnection(struct selector_key *key);
extern unsigned stm_handler_read(struct state_machine *stm, struct selector_key *key);
extern unsigned stm_handler_write(struct state_machine *stm, struct selector_key *key);
extern unsigned stm_handler_block(struct state_machine *stm, struct selector_key *key);
extern void stm_handler_close(struct state_machine *stm, struct selector_key *key);
unsigned startConnection(struct selector_key * key);
unsigned preSetRequestResponse(struct selector_key * key,int errorStatus);
// Funciones para registrar sockets en el selector
void dnsResolutionDone(union sigval sv);
static unsigned handle_request_error(int error, struct selector_key *key);


static void cleanup_previous_resolution(ClientData *clientData) {
    if (clientData->originResolution != NULL) {
        if (clientData->resolution_from_getaddrinfo) {
            freeaddrinfo(clientData->originResolution);
        } else {
            if (clientData->originResolution->ai_addr != NULL) {
                free(clientData->originResolution->ai_addr);
            }
            free(clientData->originResolution);
        }
        clientData->originResolution = NULL;
        clientData->resolution_from_getaddrinfo = false;
    }
}



// Función auxiliar para crear addrinfo para IPs directas
static bool create_direct_addrinfo(ClientData *clientData, resolver_parser *parser) {
    // Limpiar resolución previa si existe
    cleanup_previous_resolution(clientData);

    if (parser->address_type == ATYP_IPV4) {
        struct sockaddr_in* ipv4_addr = malloc(sizeof(struct sockaddr_in));
        if (ipv4_addr == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for IPv4");
            return false;
        }

        clientData->originResolution = calloc(1, sizeof(struct addrinfo));
        if(clientData->originResolution == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for addrinfo IPv4");
            free(ipv4_addr);
            return false;
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

        clientData->resolution_from_getaddrinfo = false;
        return true;

    } else if (parser->address_type == ATYP_IPV6) {
        struct sockaddr_in6* ipv6_addr = malloc(sizeof(struct sockaddr_in6));
        if (ipv6_addr == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for IPv6");
            return false;
        }

        clientData->originResolution = calloc(1, sizeof(struct addrinfo));
        if(clientData->originResolution == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for addrinfo IPv6");
            free(ipv6_addr);
            return false;
        }

        *ipv6_addr = (struct sockaddr_in6){
            .sin6_family = AF_INET6,
            .sin6_port = htons(parser->port),
        };
        memcpy(&ipv6_addr->sin6_addr, parser->ipv6_addr, 16);

        *clientData->originResolution = (struct addrinfo){
            .ai_family = AF_INET6,
            .ai_addrlen = sizeof(*ipv6_addr),
            .ai_addr = (struct sockaddr *)ipv6_addr,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP
        };

        clientData->resolution_from_getaddrinfo = false;
        return true;
    }

    return false;
}

// Funciones para la máquina de estados

void requestReadInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    initResolverParser(&clientData->client.reqParser);
    LOG_DEBUG("%s" ,"REQ_READ_INIT: Starting SOCKS5 request reading (state = %d)", state);
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

    request_parse result = resolverParse(parser, &clientData->clientBuffer);

    switch (result) {
        case REQUEST_PARSE_INCOMPLETE:
            return REQ_READ;

        case REQUEST_PARSE_OK:
            LOG_DEBUG("REQ_READ: Request parsed successfully - Command: %d, AddressType: %d, Port: %d", 
                     parser->command, parser->address_type, parser->port);
            
            // Capturar información del destino para logging de acceso
            clientData->target_port = parser->port;

            if (parser->address_type == ATYP_DOMAIN) {
                LOG_DEBUG("REQ_READ: Target domain: %.*s", parser->domain_length, parser->domain);
                // Copiar dominio para logging
                int copy_len = parser->domain_length < sizeof(clientData->target_host) - 1 ? 
                              parser->domain_length : sizeof(clientData->target_host) - 1; // todo: chequear esto
                memcpy(clientData->target_host, parser->domain, copy_len);
                clientData->target_host[copy_len] = '\0'; // todo:chequear (LOGS)
            } else if (parser->address_type == ATYP_IPV4) {
                LOG_DEBUG("REQ_READ: Target IPv4: %d.%d.%d.%d", 
                         parser->ipv4_addr[0], parser->ipv4_addr[1], 
                         parser->ipv4_addr[2], parser->ipv4_addr[3]);
                // Convertir IPv4 a string para logging
                snprintf(clientData->target_host, sizeof(clientData->target_host), 
                        "%d.%d.%d.%d", parser->ipv4_addr[0], parser->ipv4_addr[1], 
                        parser->ipv4_addr[2], parser->ipv4_addr[3]);
            } else if (parser->address_type == ATYP_IPV6) {
                LOG_DEBUG("%s" , "REQ_READ: Target IPv6");
                // Convertir IPv6 a string para logging
                inet_ntop(AF_INET6, parser->ipv6_addr, clientData->target_host, 
                         sizeof(clientData->target_host));
            }

            // Por ahora solo soportamos CONNECT
            if (parser->command != CMD_CONNECT) {
                LOG_WARN("REQ_READ: Unsupported command (%d), sending error", parser->command);
                clientData->socks_status = 0x07; // Command not supported
                // Enviar error: Command not supported
                return preSetRequestResponse(key, COMMAND_NOT_SUPPORTED); // Command not supported
            }

            // Optimización: Para IPv4/IPv6 directas, saltear ADDR_RESOLVE
            if (parser->address_type == ATYP_IPV4 || parser->address_type == ATYP_IPV6) {
                if (create_direct_addrinfo(clientData, parser)) {
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    return startConnection(key);
                }
                LOG_ERROR("%s" ,"REQ_READ: Failed to create addrinfo for direct IP");
                clientData->socks_status = 0x01; // General SOCKS server failure
                return preSetRequestResponse(key, GENERAL_FAILURE); // General SOCKS server failure

            }

            // Para dominios, necesitamos resolver con DNS
            return ADDR_RESOLVE;

        case REQUEST_PARSE_ERROR:
            LOG_ERROR("%s" , "REQ_READ: Error parsing request");
            clientData->socks_status = 0x01; // General SOCKS server failure
            // Enviar error: General SOCKS server failure
            return preSetRequestResponse(key, GENERAL_FAILURE); // General SOCKS server failure
    }

    return ERROR;
}

unsigned requestWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    if (buffer_can_read(&clientData->originBuffer)) {
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
        // ssize_t bytes_written = write(clientData->clientFd, write_ptr, bytes_to_write);
        ssize_t bytes_written = send(clientData->clientFd, write_ptr, bytes_to_write, MSG_NOSIGNAL);
        // todo: cambie las lineas de arriba, revisen porfa. mati

        if (bytes_written < 0) {
            LOG_ERROR("%s","REQ_WRITE: Error writing to client");
            return ERROR;
        }

        buffer_read_adv(&clientData->originBuffer, bytes_written);

        if (buffer_can_read(&clientData->originBuffer)) {
            return REQ_WRITE;
        }
    }

    return CLOSED;
}

void addressResolveInit(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("ADDR_RESOLVE_INIT: Starting address resolution (state = %d)", state);

    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Limpiar resolución previa si existe
    cleanup_previous_resolution(clientData);


    // Configurar estructura DNS
    struct dns_request *dns_req = &clientData->dns_req;
    snprintf(dns_req->port, sizeof(dns_req->port), "%u", (parser->port));
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
    sev.sigev_value.sival_ptr = dns_req;

    if (getaddrinfo_a(GAI_NOWAIT, reqs, 1, &sev) != 0) {
        LOG_ERROR("%s","ADDR_RESOLVE_INIT: Error starting DNS resolution");
        // sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
        clientData->dns_resolution_state = -1;
        if (selector_set_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
            closeConnection(key);
        }

        return;
    }

    // Desactivar eventos hasta que termine la resolución DNS
    clientData->dns_resolution_state = 1; // En progreso
    if(selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s" ,"ADDR_RESOLVE_INIT: Error disabling events");
        closeConnection(key);
        return;
    }



}

unsigned addressResolveDone(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;


    // Como probamos, la única forma de llegar a este estado es con un ATYP_DOMAIN.
    // Por lo tanto, toda la lógica puede centrarse en el resultado de la resolución DNS,
    // que se comunica a través del flag `dns_resolution_state`.

    if (clientData->dns_resolution_state == 2) {
        // DNS completada exitosamente
        clientData->dns_resolution_state = 0; // Reseteamos el flag
        return startConnection(key);

    }
    if (clientData->dns_resolution_state == 1) {
        // DNS aún en progreso. Nos mantenemos en el estado.
        return ADDR_RESOLVE;

    }
    // Cubre el fallo del DNS (estado -1) y el fallo en init (estado 0)
    // DNS falló o hubo un error inmediato al iniciar la resolución.
    LOG_ERROR("%s" , "ADDR_RESOLVE_DONE: DNS failed or init error");
    clientData->dns_resolution_state = 0; // Reseteamos el flag
    return preSetRequestResponse(key, GENERAL_FAILURE); // General SOCKS server failure

}



unsigned requestConnecting(struct selector_key *key) {

    if (key == NULL || key->data == NULL) {
        LOG_ERROR("%s" ,"requestConnecting: key or key->data is NULL");
        return ERROR;
    }

    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Si la conexión ya estaba marcada como lista, proceder
    if (clientData->connection_ready) {
        LOG_DEBUG("%s" , "requestConnecting: Connection was already ready");
    } else {
        // Verificar si la conexión se completó exitosamente
        int so_error = 0;
        socklen_t len = sizeof(so_error);

        if (getsockopt(clientData->originFd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
            LOG_ERROR("requestConnecting: Error in getsockopt: %s", strerror(errno));
            return preSetRequestResponse(key, GENERAL_FAILURE);
        }
        LOG_DEBUG("requestConnecting: getsockopt SO_ERROR = %d (%s)", so_error, strerror(so_error));


        if (so_error != 0) {
            printf("[DEBUG] requestConnecting: Error en conexión: %s\n", strerror(so_error));

            //selector_unregister_fd(key->s, clientData->originFd);
            clientData->unregistering_origin = true;
            selector_unregister_fd(key->s, clientData->originFd);
            clientData->unregistering_origin = false;
            close(clientData->originFd);

            if (clientData->resolution_from_getaddrinfo && clientData->originResolution->ai_next != NULL) {
                clientData->originResolution = clientData->originResolution->ai_next;
                return startConnection(key);
            }

            // Si no hay más direcciones o la resolución es manual, liberar memoria y responder error

//            selector_unregister_fd(key->s, clientData->originFd);
//            close(clientData->originFd);

            return handle_request_error(so_error, key);

        }

        clientData->connection_ready = 1;
    }

    // Obtener la dirección local del socket para la respuesta
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(clientData->originFd, (struct sockaddr*)&local_addr, &local_addr_len) < 0) {
        LOG_DEBUG("%s" ,"requestConnecting: Error getting local address");
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
    // Configurar cliente para escribir la respuesta
    if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE) != SELECTOR_SUCCESS || !prepareRequestResponse(&clientData->originBuffer, 0x05, SUCCESS, ATYP_IPV4, parser->ipv4_addr, 0)) {
        LOG_ERROR("%s" ,"requestConnecting: Error configuring client for writing");
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
                return CONNECTING;
            }
            LOG_ERROR("requestConnecting: Error writing response: %s", strerror(errno));
            return ERROR;
        }

        buffer_read_adv(&clientData->originBuffer, bytes_written);

        if (buffer_can_read(&clientData->originBuffer)) {
            return CONNECTING;
        }
    }

    return COPYING;
}



void dnsResolutionDone(union sigval sv) {
    struct dns_request *dns_req = sv.sival_ptr;
    ClientData *clientData = (ClientData *)dns_req->clientData;

    int ret = gai_error(&dns_req->req);
    if (ret != 0) {
        LOG_ERROR("DNS resolution error: %s", gai_strerror(ret));
        if (dns_req->req.ar_result != NULL) {
            freeaddrinfo(dns_req->req.ar_result);
        }
        clientData->dns_resolution_state = -1;
        //SEM_UP
        selector_notify_block(dns_req->selector, dns_req->fd);
        return;
    }
    
    clientData->originResolution = dns_req->req.ar_result;
    clientData->resolution_from_getaddrinfo = true;  // Memoria de getaddrinfo_a
    clientData->dns_resolution_state = 2; // Indica que la resolución se completó exitosamente
    //SEM_UP
    
    selector_notify_block(dns_req->selector, dns_req->fd);
    }

unsigned startConnection(struct selector_key * key) {
    ClientData *clientData = (ClientData *)key->data;


    struct addrinfo *ai = clientData->originResolution;
    clientData->originFd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (clientData->originFd < 0) {
        LOG_ERROR("CONNECTING_INIT: ai->ai_family: %d, ai->ai_socktype: %d, ai->ai_protocol: %d",
                  ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        LOG_ERROR("CONNECTING_INIT: Error creating socket: %s", strerror(errno));
        return preSetRequestResponse(key, GENERAL_FAILURE);
    }
    if(selector_set_interest(key->s, clientData->clientFd, OP_NOOP) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s" ,"CONNECTING_INIT: Error disabling client events");
        close(clientData->originFd);
        return ERROR;
    }

    selector_fd_set_nio(clientData->originFd);
    LOG_DEBUG("CONNECTING_INIT: Socket created (fd=%d), attempting to connect", clientData->originFd);

    int connect_result = connect(clientData->originFd, ai->ai_addr, ai->ai_addrlen);

    if (connect_result == 0) {
        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            LOG_ERROR("%s" , "CONNECTING_INIT: Error registering origin socket (immediate)");
            close(clientData->originFd);
            return ERROR;
        }
        selector_set_interest(key->s, key->fd, OP_WRITE);
        clientData->connection_ready = 1;

    } else if (errno == EINPROGRESS) {
        LOG_DEBUG("%s ", "CONNECTING_INIT: Connection in progress (EINPROGRESS)");

        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            LOG_ERROR("%s" ,"CONNECTING_INIT: Error registering origin socket (in progress)");
            close(clientData->originFd);
            return ERROR;
        }
        clientData->connection_ready = 0;

    } else {
        LOG_ERROR("CONNECTING_INIT: Error connecting: %s", strerror(errno));
        clientData->unregistering_origin = true;
        selector_unregister_fd(key->s, clientData->originFd);
        clientData->unregistering_origin = false;
        close(clientData->originFd);

        if (clientData->originResolution->ai_next != NULL) {
            struct addrinfo* next = clientData->originResolution->ai_next;
            clientData->originResolution = next;
            return startConnection(key);
        }

        return handle_request_error(errno, key);
    }

    return CONNECTING;
}



static unsigned handle_request_error(int error, struct selector_key *key) {
    switch (error) {
        case ECONNREFUSED:
            LOG_ERROR("%s" ,"requestConnecting: Connection refused");
            return preSetRequestResponse(key, CONNECTION_REFUSED);
        case ENETUNREACH:
            LOG_ERROR("%s" ,"requestConnecting: Network unreachable");
            return preSetRequestResponse(key, NETWORK_UNREACHABLE);
        case EHOSTUNREACH:
            LOG_ERROR("%s" ,"requestConnecting: Host unreachable");
            return preSetRequestResponse(key, HOST_UNREACHABLE);
        case ETIMEDOUT:
            LOG_ERROR("%s" , "requestConnecting: TTL expired / Timeout");
            return preSetRequestResponse(key, TTL_EXPIRED);
        case EACCES:
            LOG_ERROR("%s" ,"requestConnecting: Connection not allowed");
            return preSetRequestResponse(key, NOT_ALLOWED);
        default:
            LOG_ERROR("%s" ,"requestConnecting: General SOCKS server failure");
            return preSetRequestResponse(key, GENERAL_FAILURE);
    }
}


unsigned preSetRequestResponse(struct selector_key * key,int errorStatus){
    ClientData *clientData = (ClientData *)key->data;
    if(!prepareRequestResponse(&clientData->originBuffer, 0x05, errorStatus, ATYP_IPV4, clientData->client.reqParser.ipv4_addr, 0) || selector_set_interest(key->s,clientData->clientFd,OP_WRITE) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s" , "preSetRequestResponse: Error preparing request response");
        return ERROR;
    }
    return REQ_WRITE;
}