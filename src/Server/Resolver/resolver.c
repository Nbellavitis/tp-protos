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
static bool create_direct_addrinfo(ClientData *clientData, const resolver_parser *parser) {
    // Limpiar resolución previa si existe
    cleanup_previous_resolution(clientData);

    if (parser->address_type == ATYP_IPV4) {
        struct sockaddr_in* ipv4_addr = malloc(sizeof(struct sockaddr_in));
        if (ipv4_addr == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for IPv4");
            return false;
        }

        clientData->originResolution = calloc(1, sizeof(struct addrinfo)); // todo: magic number
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
        clientData->currentResolution = clientData->originResolution;
        return true;

    } else if (parser->address_type == ATYP_IPV6) {
        struct sockaddr_in6* ipv6_addr = malloc(sizeof(struct sockaddr_in6));
        if (ipv6_addr == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for IPv6");
            return false;
        }

        clientData->originResolution = calloc(1, sizeof(struct addrinfo)); // todo magic number
        if(clientData->originResolution == NULL) {
            LOG_ERROR("%s" ,"create_direct_addrinfo: Error allocating memory for addrinfo IPv6");
            free(ipv6_addr);
            return false;
        }

        *ipv6_addr = (struct sockaddr_in6){
            .sin6_family = AF_INET6,
            .sin6_port = htons(parser->port),
        };
        memcpy(&ipv6_addr->sin6_addr, parser->ipv6_addr, IPV6_ADDR_SIZE);

        *clientData->originResolution = (struct addrinfo){
            .ai_family = AF_INET6,
            .ai_addrlen = sizeof(*ipv6_addr),
            .ai_addr = (struct sockaddr *)ipv6_addr,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP
        };

        clientData->resolution_from_getaddrinfo = false;
        clientData->currentResolution = clientData->originResolution;
        return true;
    }

    return false;
}

// Funciones para la máquina de estados

void requestReadInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    initResolverParser(&clientData->client.reqParser);
}

unsigned requestRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;

    // Leer del socket al buffer
    size_t writeLimit;
    uint8_t *b = buffer_write_ptr(&clientData->clientBuffer, &writeLimit);
    const ssize_t readCount = recv(key->fd, b, writeLimit, 0); // todo: magic number
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    buffer_write_adv(&clientData->clientBuffer, readCount);

    const request_parse result = resolverParse(parser, &clientData->clientBuffer);

    if (result == REQUEST_PARSE_INCOMPLETE) {
        return REQ_READ;
    }

    if (result == REQUEST_PARSE_ERROR) {
        LOG_ERROR("%s" , "REQ_READ: Error parsing request");
        clientData->socks_status = GENERAL_FAILURE;
        // Enviar error: General SOCKS server failure
        return preSetRequestResponse(key, GENERAL_FAILURE);
    }

    if (result != REQUEST_PARSE_OK) {
        return ERROR;
    }


    LOG_DEBUG("REQ_READ: Request parsed successfully - Command: %d, AddressType: %d, Port: %d", parser->command, parser->address_type, parser->port);

    // Capturar información del destino para logging de acceso
    clientData->target_port = parser->port;

    if (parser->address_type == ATYP_DOMAIN) {
        LOG_DEBUG("REQ_READ: Target domain: %.*s", parser->domain_length, parser->domain);
        // Copiar dominio para logging
        int copy_len = parser->domain_length < sizeof(clientData->target_host) - 1 ? parser->domain_length : sizeof(clientData->target_host) - 1; // todo: chequear esto
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
        clientData->socks_status = COMMAND_NOT_SUPPORTED; // Command not supported
        // Enviar error: Command not supported
        return preSetRequestResponse(key, COMMAND_NOT_SUPPORTED); // Command not supported
    }

    if (parser->address_type != ATYP_IPV4 && parser->address_type != ATYP_IPV6) {
        // Para dominios, necesitamos resolver con DNS
        return ADDR_RESOLVE;
    }

    // Para IPv4/IPv6 directas, saltear ADDR_RESOLVE
    if (!create_direct_addrinfo(clientData, parser)) {
        LOG_ERROR("%s" ,"REQ_READ: Failed to create addrinfo for direct IP");
        clientData->socks_status = GENERAL_FAILURE;
        return preSetRequestResponse(key, GENERAL_FAILURE);
    }

    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) { // todo: el selector no lo tendría que hacer después del startConnection?
        return ERROR;
    }
    return startConnection(key);
}


unsigned requestWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    if (!buffer_flush(&clientData->originBuffer, clientData->clientFd, NULL)) {
        return ERROR;
    }

    if (buffer_can_read(&clientData->originBuffer)) {
        return REQ_WRITE;
    }

    if (clientData->socks_status == SUCCESS) {
        return COPYING;
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

    if (getaddrinfo_a(GAI_NOWAIT, reqs, GETADDRINFO_A_COUNT, &sev) != 0) {
        LOG_ERROR("%s","ADDR_RESOLVE_INIT: Error starting DNS resolution");
        // sendRequestResponse(&clientData->originBuffer, 0x05, 0x01, ATYP_IPV4, parser->ipv4_addr, 0);
        clientData->dns_resolution_state = DNS_STATE_ERROR;
        if (selector_set_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
            closeConnection(key);
        }

        return;
    }

    // Desactivar eventos hasta que termine la resolución DNS
    clientData->dns_resolution_state = DNS_STATE_IN_PROGRESS;
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

    if (clientData->dns_resolution_state == DNS_STATE_COMPLETED) {
        // DNS completada exitosamente
        clientData->dns_resolution_state = DNS_STATE_IDLE; // Reseteamos el flag
        clientData->currentResolution = clientData->originResolution;
        return startConnection(key);

    }
    if (clientData->dns_resolution_state == DNS_STATE_IN_PROGRESS) {
        // DNS aún en progreso. Nos mantenemos en el estado.
        return ADDR_RESOLVE;

    }
    // Cubre el fallo del DNS (estado -1) y el fallo en init (estado 0)
    // DNS falló o hubo un error inmediato al iniciar la resolución.
//    LOG_ERROR("%s" , "ADDR_RESOLVE_DONE: DNS failed or init error");
    clientData->dns_resolution_state = DNS_STATE_IDLE; // Reseteamos el flag
    return preSetRequestResponse(key, GENERAL_FAILURE); // General SOCKS server failure

}


unsigned requestConnecting(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    if (clientData->connection_ready) {
        clientData->socks_status = SUCCESS;
        return preSetRequestResponse(key, SUCCESS);
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(clientData->originFd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        return handle_request_error(errno, key);
    }

    if (so_error != 0) {
        // Falló la conexión, intentamos con la siguiente dirección.
        clientData->unregistering_origin = true;
        selector_unregister_fd(key->s, clientData->originFd);
        clientData->unregistering_origin = false;
        close(clientData->originFd);

        if (clientData->resolution_from_getaddrinfo && clientData->currentResolution->ai_next != NULL) {
            clientData->currentResolution = clientData->currentResolution->ai_next;
            return startConnection(key);
        }

        return handle_request_error(so_error, key);
    }

    clientData->connection_ready = CONNECTION_READY;
    clientData->socks_status = SUCCESS;
    return preSetRequestResponse(key, SUCCESS);
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
        clientData->dns_resolution_state = DNS_STATE_ERROR;
        //SEM_UP
        selector_notify_block(dns_req->selector, dns_req->fd);
        return;
    }
    
    clientData->originResolution = dns_req->req.ar_result;
    clientData->resolution_from_getaddrinfo = true;  // Memoria de getaddrinfo_a
    clientData->dns_resolution_state = DNS_STATE_COMPLETED; // Indica que la resolución se completó exitosamente
    //SEM_UP
    
    selector_notify_block(dns_req->selector, dns_req->fd);
    }

unsigned startConnection(struct selector_key * key) {
    ClientData *clientData = (ClientData *)key->data;


    struct addrinfo *ai = clientData->currentResolution;

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
        // Conexión inmediata (muuy extraño)
        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            LOG_ERROR("%s" , "CONNECTING_INIT: Error registering origin socket (immediate)");
            close(clientData->originFd);
            return ERROR;
        }
        selector_set_interest(key->s, key->fd, OP_WRITE);
        clientData->connection_ready = CONNECTION_READY;
        return CONNECTING;
    }

    if (errno == EINPROGRESS) {
        LOG_DEBUG("%s ", "CONNECTING_INIT: Connection in progress (EINPROGRESS)");

        if (selector_register(key->s, clientData->originFd, getSocksv5Handler(), OP_WRITE, clientData)) {
            LOG_ERROR("%s" ,"CONNECTING_INIT: Error registering origin socket (in progress)");
            close(clientData->originFd);
            return ERROR;
        }
        clientData->connection_ready = CONNECTION_NOT_READY;
        return CONNECTING;
    }

//    LOG_ERROR("CONNECTING_INIT: Error connecting: %s", strerror(errno));
    clientData->unregistering_origin = true;
    selector_unregister_fd(key->s, clientData->originFd);
    clientData->unregistering_origin = false;
    close(clientData->originFd);

    if (clientData->currentResolution->ai_next != NULL) {
        struct addrinfo* next = clientData->currentResolution->ai_next;
        clientData->currentResolution = next;
        return startConnection(key);
    }

    return handle_request_error(errno, key);


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

unsigned preSetRequestResponse(struct selector_key *key, int errorStatus) {
    ClientData *clientData = (ClientData *)key->data;
    clientData->socks_status = errorStatus;

    // valores fallback
    uint8_t  atyp = ATYP_IPV4;
    uint16_t port = 0;
    uint8_t  addr[IPV6_ADDR_SIZE] = {0};

    if (clientData->originFd >= 0 && errorStatus == SUCCESS) {
        struct sockaddr_storage local_addr;
        socklen_t local_addr_len = sizeof(local_addr);

        if (getsockname(clientData->originFd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
            if (local_addr.ss_family == AF_INET) {
                const struct sockaddr_in *addr4 = (struct sockaddr_in *)&local_addr;
                atyp = ATYP_IPV4;
                port = ntohs(addr4->sin_port);
                memcpy(addr, &addr4->sin_addr, IPV4_ADDR_SIZE);
            } else if (local_addr.ss_family == AF_INET6) {
                const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&local_addr;
                atyp = ATYP_IPV6;
                port = ntohs(addr6->sin6_port);
                memcpy(addr, &addr6->sin6_addr, IPV6_ADDR_SIZE);
            }
        }
    }

    if (!prepareRequestResponse(&clientData->originBuffer, SOCKS5_VERSION, errorStatus, atyp, addr, port) ||
        selector_set_interest(key->s, clientData->clientFd, OP_WRITE) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s", "preSetRequestResponse: Error preparing request response");
        return ERROR;
        }

    return REQ_WRITE;
}


// todo: eventualmente eliminar lo de abajo. Lo deje comentado por si acaso, es la versión anterior de la funcion
// unsigned preSetRequestResponse(struct selector_key *key, int errorStatus) {
//     ClientData *clientData = (ClientData *)key->data;
//     clientData->socks_status = errorStatus; //@todo checkear.
//
//     uint8_t atyp = ATYP_IPV4;
//     uint8_t addr[IPV6_ADDR_SIZE];
//     uint16_t port = 0;
//
//     if (clientData->originFd >= 0) {
//         struct sockaddr_storage local_addr;
//         socklen_t local_addr_len = sizeof(local_addr);
//
//         if (getsockname(clientData->originFd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
//             if (local_addr.ss_family == AF_INET) {
//                 struct sockaddr_in *addr4 = (struct sockaddr_in *)&local_addr;
//                 memcpy(addr, &addr4->sin_addr, IPV4_ADDR_SIZE); // todo: magic number ?
//                 port = ntohs(addr4->sin_port);
//                 atyp = ATYP_IPV4;
//             } else if (local_addr.ss_family == AF_INET6) {
//                 struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&local_addr;
//                 memcpy(addr, &addr6->sin6_addr, IPV6_ADDR_SIZE);
//                 port = ntohs(addr6->sin6_port);
//                 atyp = ATYP_IPV6;
//             } else {
//                 // Fallback si no es una familia válida
//                 uint32_t ip = htonl(0);
//                 memcpy(addr, &ip, IPV4_ADDR_SIZE);
//                 port = 0;
//                 atyp = ATYP_IPV4;
//             }
//         } else {
//             // getsockname falló → fallback
//             uint32_t ip = htonl(0);
//             memcpy(addr, &ip, IPV4_ADDR_SIZE);
//             port = 0;
//             atyp = ATYP_IPV4;
//         }
//     } else {
//         // originFd inválido → no se pudo conectar
//         uint32_t ip = htonl(0);
//         memcpy(addr, &ip, IPV4_ADDR_SIZE);
//         port = 0;
//         atyp = ATYP_IPV4;
//     }
//
//     if (!prepareRequestResponse(&clientData->originBuffer, SOCKS5_VERSION, errorStatus, atyp, addr, port) ||
//         selector_set_interest(key->s, clientData->clientFd, OP_WRITE) != SELECTOR_SUCCESS) {
//         LOG_ERROR("%s", "preSetRequestResponse: Error preparing request response");
//         return ERROR;
//     }
//
//     return REQ_WRITE;
// }

