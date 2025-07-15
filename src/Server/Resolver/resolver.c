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
unsigned start_connection(struct selector_key * key);
unsigned preset_request_response(struct selector_key * key,int errorStatus);
// Funciones para registrar sockets en el selector
void dns_resolution_done(union sigval sv);
static unsigned handle_request_error(int error, struct selector_key *key);


static void cleanup_previous_resolution(client_data *data) {
    if (data->origin_resolution != NULL) {
        if (data->resolution_from_getaddrinfo) {
            freeaddrinfo(data->origin_resolution);
        } else {
            if (data->origin_resolution->ai_addr != NULL) {
                free(data->origin_resolution->ai_addr);
            }
            free(data->origin_resolution);
        }
        data->origin_resolution = NULL;
        data->resolution_from_getaddrinfo = false;
    }
}



static struct sockaddr_in *create_sockaddr_ipv4(const resolver_parser *parser) {
    struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
    if (addr == NULL) {
        LOG_ERROR("%s", "create_sockaddr_ipv4: Error allocating memory");
        return NULL;
    }

    addr->sin_family = AF_INET;
    addr->sin_port = htons(parser->port);
    memcpy(&addr->sin_addr, parser->ipv4_addr, IPV4_ADDR_SIZE);

    return addr;
}

static struct sockaddr_in6 *create_sockaddr_ipv6(const resolver_parser *parser) {
    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (addr == NULL) {
        LOG_ERROR("%s", "create_sockaddr_ipv6: Error allocating memory");
        return NULL;
    }

    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(parser->port);
    memcpy(&addr->sin6_addr, parser->ipv6_addr, IPV6_ADDR_SIZE);

    return addr;
}

// Función auxiliar para crear addrinfo para IPs directas
static bool create_direct_addrinfo(client_data *data, const resolver_parser *parser) {
    cleanup_previous_resolution(data);

    data->origin_resolution = calloc(1, sizeof(struct addrinfo));
    if (data->origin_resolution == NULL) {
        LOG_ERROR("%s", "create_direct_addrinfo: Error allocating memory for addrinfo");
        return false;
    }

    struct sockaddr *sock_addr = NULL;
    if (parser->address_type == ATYP_IPV4) {
        sock_addr = (struct sockaddr *)create_sockaddr_ipv4(parser);
        data->origin_resolution->ai_family = AF_INET;
        data->origin_resolution->ai_addrlen = sizeof(struct sockaddr_in);
    } else if (parser->address_type == ATYP_IPV6) {
        sock_addr = (struct sockaddr *)create_sockaddr_ipv6(parser);
        data->origin_resolution->ai_family = AF_INET6;
        data->origin_resolution->ai_addrlen = sizeof(struct sockaddr_in6);
    }

    if (sock_addr == NULL) {
        free(data->origin_resolution);
        data->origin_resolution = NULL;
        return false;
    }

    data->origin_resolution->ai_addr = sock_addr;
    data->origin_resolution->ai_socktype = SOCK_STREAM;
    data->origin_resolution->ai_protocol = IPPROTO_TCP;

    data->resolution_from_getaddrinfo = false;
    data->current_resolution = data->origin_resolution;

    return true;
}


// Funciones para la máquina de estados
void request_read_init(const unsigned state, struct selector_key *key) {
    client_data *data = (client_data *)key->data;
    init_resolver_parser(&data->client.req_parser);
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        close_connection(key);
    }
}

// Función auxiliar para capturar información para el logging
static void capture_target_info(client_data *data) {
    resolver_parser *parser = &data->client.req_parser;
    data->target_port = parser->port;

    if (parser->address_type == ATYP_DOMAIN) {
        LOG_DEBUG("REQ_READ: Target domain: %.*s", parser->domain_length, parser->domain);
        int copy_len = parser->domain_length < sizeof(data->target_host) - 1 ? parser->domain_length : sizeof(data->target_host) - 1;
        memcpy(data->target_host, parser->domain, copy_len);
        data->target_host[copy_len] = '\0';

    } else if (parser->address_type == ATYP_IPV4) {
        LOG_DEBUG("REQ_READ: Target IPv4: %d.%d.%d.%d",
                 parser->ipv4_addr[0], parser->ipv4_addr[1],
                 parser->ipv4_addr[2], parser->ipv4_addr[3]);
        snprintf(data->target_host, sizeof(data->target_host),
                "%d.%d.%d.%d", parser->ipv4_addr[0], parser->ipv4_addr[1],
                parser->ipv4_addr[2], parser->ipv4_addr[3]);

    } else if (parser->address_type == ATYP_IPV6) {
        LOG_DEBUG("%s", "REQ_READ: Target IPv6");
        inet_ntop(AF_INET6, parser->ipv6_addr, data->target_host,
                 sizeof(data->target_host));
    }
}

unsigned request_read(struct selector_key *key) {
    client_data *data = (client_data *)key->data;
    resolver_parser *parser = &data->client.req_parser;

    // Leer del socket al buffer
    size_t writeLimit;
    uint8_t *b = buffer_write_ptr(&data->client_buffer, &writeLimit);
    const ssize_t readCount = recv(key->fd, b, writeLimit, 0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    buffer_write_adv(&data->client_buffer, readCount);

    const request_parse result = resolver_parse(parser, &data->client_buffer);

    if (result == REQUEST_PARSE_INCOMPLETE) {
        return REQ_READ;
    }

    if (result == REQUEST_PARSE_ERROR) {
        LOG_ERROR("%s" , "REQ_READ: Error parsing request");
        data->socks_status = GENERAL_FAILURE;
        return preset_request_response(key, GENERAL_FAILURE);
    }

    if (result != REQUEST_PARSE_OK) {
        LOG_ERROR("REQ_READ: Unexpected parse result: %d", result);
        return ERROR;
    }

    // Capturar información para logging de acceso
    capture_target_info(data);


    if (parser->command != CMD_CONNECT) {
        LOG_WARN("REQ_READ: Unsupported command (%d), sending error", parser->command);
        data->socks_status = COMMAND_NOT_SUPPORTED;
        return preset_request_response(key, COMMAND_NOT_SUPPORTED);
    }

    if (parser->address_type != ATYP_IPV4 && parser->address_type != ATYP_IPV6) {
        return ADDR_RESOLVE;
    }

    // Para IPv4/IPv6 directas, saltear ADDR_RESOLVE
    if (!create_direct_addrinfo(data, parser)) {
        LOG_ERROR("%s" ,"REQ_READ: Failed to create addrinfo for direct IP");
        data->socks_status = GENERAL_FAILURE;
        return preset_request_response(key, GENERAL_FAILURE);
    }

    return start_connection(key);
}

void request_write_init(const unsigned state, struct selector_key *key) {
    const client_data *data = (client_data *)key->data;

    if (selector_set_interest(key->s, data->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        close_connection(key);
        return;
    }

    if (data->origin_fd >= 0 && selector_set_interest(key->s, data->origin_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        close_connection(key);
    }
}

unsigned request_write(struct selector_key *key) {
    client_data *data = (client_data *)key->data;

    if (!buffer_flush(&data->origin_buffer, data->client_fd, NULL)) {
        return ERROR;
    }

    if (buffer_can_read(&data->origin_buffer)) {
        return REQ_WRITE;
    }

    if (data->socks_status == SUCCESS) {
        return COPYING;
    }

    return CLOSED;

}

void address_resolve_init(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("ADDR_RESOLVE_INIT: Starting address resolution (state = %d)", state);

    client_data *data = (client_data *)key->data;
    resolver_parser *parser = &data->client.req_parser;

    // Limpiar resolución previa si existe
    cleanup_previous_resolution(data);


    // Configurar estructura DNS
    struct dns_request *dns_req = &data->dns_req;
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
    dns_req->client_data = data;
    dns_req->selector = key->s;
    dns_req->fd = key->fd;

    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = dns_resolution_done;
    sev.sigev_value.sival_ptr = dns_req;

    if (getaddrinfo_a(GAI_NOWAIT, reqs, GETADDRINFO_A_COUNT, &sev) != 0) {
        LOG_ERROR("%s","ADDR_RESOLVE_INIT: Error starting DNS resolution");
        data->dns_resolution_state = DNS_STATE_ERROR;
        if (selector_set_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
            close_connection(key);
        }

        return;
    }

    // Desactivar eventos hasta que termine la resolución DNS
    data->dns_resolution_state = DNS_STATE_IN_PROGRESS;
    if(selector_set_interest(key->s, key->fd, OP_NOOP) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s" ,"ADDR_RESOLVE_INIT: Error disabling events");
        close_connection(key);
    }

}

unsigned address_resolve_write(struct selector_key *key) {
    return preset_request_response(key, GENERAL_FAILURE);
}


unsigned address_resolve_done(struct selector_key *key, void *data) {
    // Si estamos acá es con un ATYP_DOMAIN.
    client_data *c_data = (client_data *)key->data;
    dns_result *dns_result_data = (dns_result *)data;


    if (dns_result_data->gai_error != 0) {

        free(dns_result_data);
        return preset_request_response(key, GENERAL_FAILURE);
    }

    cleanup_previous_resolution(c_data);
    c_data->origin_resolution = dns_result_data->result;
    c_data->resolution_from_getaddrinfo = true;
    c_data->current_resolution = c_data->origin_resolution;

    free(dns_result_data);

    return start_connection(key);
}


unsigned request_connecting(struct selector_key *key) {
    client_data *data = (client_data *)key->data;
    data->last_activity = time(NULL);

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        return handle_request_error(errno, key);
    }

    if (so_error != 0) {
        // Falló la conexión, intentamos con la siguiente dirección.
        data->unregistering_origin = true;
        selector_unregister_fd(key->s, data->origin_fd);
        data->unregistering_origin = false;
        close(data->origin_fd);

        if (data->resolution_from_getaddrinfo && data->current_resolution->ai_next != NULL) {
            data->current_resolution = data->current_resolution->ai_next;
            return start_connection(key);
        }

        return handle_request_error(so_error, key);
    }

    data->socks_status = SUCCESS;
    return preset_request_response(key, SUCCESS);
}



void dns_resolution_done(union sigval sv) {
    struct dns_request *dns_req = sv.sival_ptr;

    dns_result *dns_result_data = malloc(sizeof(dns_result));
    if (dns_result_data == NULL) {
        LOG_ERROR("%s", "Failed to allocate memory for DNS result message");
        return;
    }

    dns_result_data->gai_error = gai_error(&dns_req->req);
    if (dns_result_data->gai_error == 0) {
        dns_result_data->result = dns_req->req.ar_result;
    } else {
        dns_result_data->result = NULL;
        if (dns_req->req.ar_result != NULL) {
            freeaddrinfo(dns_req->req.ar_result);
        }
        LOG_ERROR("DNS resolution error: %s", gai_strerror(dns_result_data->gai_error));
    }

    selector_notify_block(dns_req->selector, dns_req->fd, dns_result_data);
}
unsigned start_connection(struct selector_key * key) {
    client_data *data = (client_data *)key->data;


    struct addrinfo *ai = data->current_resolution;

    data->origin_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (data->origin_fd < 0) {
        LOG_ERROR("CONNECTING_INIT: ai->ai_family: %d, ai->ai_socktype: %d, ai->ai_protocol: %d",
                  ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        LOG_ERROR("CONNECTING_INIT: Error creating socket: %s", strerror(errno));
        return preset_request_response(key, GENERAL_FAILURE);
    }
    if(selector_set_interest(key->s, data->client_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        LOG_ERROR("%s" ,"CONNECTING_INIT: Error disabling client events");
        close(data->origin_fd);
        return ERROR;
    }

    selector_fd_set_nio(data->origin_fd);
    LOG_DEBUG("CONNECTING_INIT: Socket created (fd=%d), attempting to connect", data->origin_fd);

    const int connect_result = connect(data->origin_fd, ai->ai_addr, ai->ai_addrlen);

    if (connect_result == 0) {
        // Conexión inmediata (muuy extraño)
        if (selector_register(key->s, data->origin_fd, get_socksv5_handler(), OP_WRITE, data)) {
            LOG_ERROR("%s" , "CONNECTING_INIT: Error registering origin socket (immediate)");
            close(data->origin_fd);
            return ERROR;
        }
        data->socks_status = SUCCESS;
        return preset_request_response(key, SUCCESS);
    }

    if (errno == EINPROGRESS) {
        LOG_DEBUG("%s ", "CONNECTING_INIT: Connection in progress (EINPROGRESS)");

        if (selector_register(key->s, data->origin_fd, get_socksv5_handler(), OP_WRITE, data)) {
            LOG_ERROR("%s" ,"CONNECTING_INIT: Error registering origin socket (in progress)");
            close(data->origin_fd);
            return ERROR;
        }
        return CONNECTING;
    }

//    LOG_ERROR("CONNECTING_INIT: Error connecting: %s", strerror(errno));
    data->unregistering_origin = true;
    selector_unregister_fd(key->s, data->origin_fd);
    data->unregistering_origin = false;
    close(data->origin_fd);

    if (data->current_resolution->ai_next != NULL) {
        struct addrinfo* next = data->current_resolution->ai_next;
        data->current_resolution = next;
        return start_connection(key);
    }

    return handle_request_error(errno, key);


}



static unsigned handle_request_error(int error, struct selector_key *key) {
    switch (error) {
        case ECONNREFUSED:
            LOG_ERROR("%s" ,"request_connecting: Connection refused");
            return preset_request_response(key, CONNECTION_REFUSED);
        case ENETUNREACH:
            LOG_ERROR("%s" ,"request_connecting: Network unreachable");
            return preset_request_response(key, NETWORK_UNREACHABLE);
        case EHOSTUNREACH:
            LOG_ERROR("%s" ,"request_connecting: Host unreachable");
            return preset_request_response(key, HOST_UNREACHABLE);
        case ETIMEDOUT:
            LOG_ERROR("%s" , "request_connecting: TTL expired / Timeout");
            return preset_request_response(key, TTL_EXPIRED);
        case EACCES:
            LOG_ERROR("%s" ,"request_connecting: Connection not allowed");
            return preset_request_response(key, NOT_ALLOWED);
        default:
            LOG_ERROR("%s" ,"request_connecting: General SOCKS server failure");
            return preset_request_response(key, GENERAL_FAILURE);
    }
}

unsigned preset_request_response(struct selector_key *key, int errorStatus) {
    client_data *data = (client_data *)key->data;
    data->socks_status = errorStatus;

    // valores fallback
    uint8_t  atyp = ATYP_IPV4;
    uint16_t port = 0;
    uint8_t  addr[IPV6_ADDR_SIZE] = {0};

    if (data->origin_fd >= 0 && errorStatus == SUCCESS) {
        struct sockaddr_storage local_addr;
        socklen_t local_addr_len = sizeof(local_addr);

        if (getsockname(data->origin_fd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
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

    if (!prepare_request_response(&data->origin_buffer, SOCKS5_VERSION, errorStatus, atyp, addr, port)) {
        LOG_ERROR("%s", "preset_request_response: Error preparing request response buffer");
        return ERROR;
    }

    return request_write(key);
}


