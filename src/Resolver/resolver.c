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

static fd_handler handler = {
     .handle_read = socksv5Read,
     .handle_write = socksv5Write,
     .handle_close = socksv5Close,
     .handle_block = socksv5Block,
};

void initResolverParser(resolver_parser *parser) {
    parser->version = 0;
    parser->command = 0;
    parser->reserved = 0;
    parser->address_type = 0;
    parser->port = 0;
    parser->state = 0;
    parser->bytes_read = 0;
    parser->done = false;
    parser->error = false;
    memset(parser->ipv4_addr, 0, 4);
    memset(parser->ipv6_addr, 0, 16);
    memset(parser->domain, 0, 256);
    parser->domain_length = 0;
}

request_parse resolverParse(resolver_parser *p, struct buffer *buffer) {
    uint8_t byte;
    
    while (buffer_can_read(buffer)) {
        byte = buffer_read(buffer);
        
        switch (p->state) {
            case 0: // VER
                if (byte != 0x05) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->version = byte;
                p->state = 1;
                break;
                
            case 1: // CMD
                if (byte != CMD_CONNECT && byte != CMD_BIND && byte != CMD_UDP_ASSOCIATE) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->command = byte;
                p->state = 2;
                break;
                
            case 2: // RSV
                if (byte != 0x00) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->reserved = byte;
                p->state = 3;
                break;
                
            case 3: // ATYP
                if (byte != ATYP_IPV4 && byte != ATYP_DOMAIN && byte != ATYP_IPV6) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->address_type = byte;
                p->state = 4;
                break;
                
            case 4: // DST.ADDR
                switch (p->address_type) {
                    case ATYP_IPV4:
                        p->ipv4_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == 4) {
                            p->state = 5;
                            p->bytes_read = 0;
                        }
                        break;
                        
                    case ATYP_DOMAIN:
                        if (p->bytes_read == 0) {
                            p->domain_length = byte;
                            p->bytes_read = 1;
                        } else {
                            p->domain[p->bytes_read - 1] = byte;
                            p->bytes_read++;
                            if (p->bytes_read > p->domain_length) {
                                p->state = 5;
                                p->bytes_read = 0;
                            }
                        }
                        break;
                        
                    case ATYP_IPV6:
                        p->ipv6_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == 16) {
                            p->state = 5;
                            p->bytes_read = 0;
                        }
                        break;
                }
                break;
                
            case 5: // DST.PORT
                if (p->bytes_read == 0) {
                    p->port = (uint16_t)byte << 8;
                    p->bytes_read = 1;
                } else {
                    p->port |= byte;
                    p->done = true;
                    return REQUEST_PARSE_OK;
                }
                break;
        }
    }
    
    return REQUEST_PARSE_INCOMPLETE;
}

bool sendRequestResponse(struct buffer *originBuffer, uint8_t version, uint8_t reply, uint8_t atyp, const void *bnd_addr, uint16_t bnd_port) {
    // Verificar espacio disponible antes de escribir
    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno, no se puede escribir\n");
        return false;
    }
    unsigned written = 0;

    // VER
    buffer_write(originBuffer, version);
    stats_add_origin_bytes(1);


    // Verificar espacio para REP
    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno después de VER\n");
        return false;
    }
    
    // REP
    buffer_write(originBuffer, reply);
    stats_add_origin_bytes(1);


    // Verificar espacio para RSV
    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno después de REP\n");
        return false;
    }
    
    // RSV
    buffer_write(originBuffer, 0x00);
    stats_add_origin_bytes(1);
    
    // Verificar espacio para ATYP
    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno después de RSV\n");
        return false;
    }
    
    // ATYP
    buffer_write(originBuffer, atyp);
    stats_add_origin_bytes(1);

    // BND.ADDR
    switch (atyp) {
        case ATYP_IPV4:
            // Verificar espacio para 4 bytes de IPv4
            if (!buffer_can_write(originBuffer)) {
                printf("[DEBUG] sendRequestResponse: Buffer lleno para IPv4\n");
                return false;
            }
            for (int i = 0; i < 4; i++) {
                if (!buffer_can_write(originBuffer)) {
                    printf("[DEBUG] sendRequestResponse: Buffer lleno durante IPv4\n");
                    return false;
                }
                buffer_write(originBuffer, ((uint8_t*)bnd_addr)[i]);
            }
            stats_add_origin_bytes(4);
            break;
        case ATYP_IPV6:
            // Verificar espacio para 16 bytes de IPv6
            if (!buffer_can_write(originBuffer)) {
                printf("[DEBUG] sendRequestResponse: Buffer lleno para IPv6\n");
                return false;
            }
            for (int i = 0; i < 16; i++) {
                if (!buffer_can_write(originBuffer)) {
                    printf("[DEBUG] sendRequestResponse: Buffer lleno durante IPv6\n");
                    return false;
                }
                buffer_write(originBuffer, ((uint8_t*)bnd_addr)[i]);
            }
            stats_add_origin_bytes(16);

            break;
        case ATYP_DOMAIN: {
            uint8_t domain_len = strlen((char*)bnd_addr);
            // Verificar espacio para longitud
            if (!buffer_can_write(originBuffer)) {
                printf("[DEBUG] sendRequestResponse: Buffer lleno para longitud de dominio\n");
                return false;
            }
            buffer_write(originBuffer, domain_len);
            
            // Verificar espacio para dominio
            for (int i = 0; i < domain_len; i++) {
                if (!buffer_can_write(originBuffer)) {
                    printf("[DEBUG] sendRequestResponse: Buffer lleno durante dominio\n");
                    return false;
                }
                buffer_write(originBuffer, ((char*)bnd_addr)[i]);
                stats_add_origin_bytes(1);  //@TODO esto es ineficiente. pero maneja el error inherentemente ni idea ver
            }
            break;
        }
    }
    
    // Verificar espacio para puerto (2 bytes)
    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno para puerto\n");
        return false;
    }
    
    // BND.PORT (network byte order)
    uint16_t port_network = htons(bnd_port);
    buffer_write(originBuffer, (port_network >> 8) & 0xFF);
    stats_add_origin_bytes(1);

    if (!buffer_can_write(originBuffer)) {
        printf("[DEBUG] sendRequestResponse: Buffer lleno para segundo byte de puerto\n");
        return false;
    }
    
    buffer_write(originBuffer, port_network & 0xFF);
    stats_add_origin_bytes(1);

    printf("[DEBUG] sendRequestResponse: Respuesta SOCKS5 enviada al buffer\n");
    return true;
}

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
    stats_add_client_bytes(readCount);  //@todo checkear todos los lugares donde poner esto

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
    
    // Si la resolución fue exitosa, configurar el selector para escritura
    if (next == CONNECTING) {
        printf("[DEBUG] ADDR_RESOLVE_INIT: Configurando selector para escritura\n");
        selector_set_interest(key->s, key->fd, OP_WRITE);
    }
}

unsigned addressResolveDone(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    resolver_parser *parser = &clientData->client.reqParser;
    
    printf("[DEBUG] ADDR_RESOLVE: Iniciando resolución de dirección\n");

    // Limpiar resolución previa si existe
    if (clientData->originResolution != NULL) {
        freeaddrinfo(clientData->originResolution);
        clientData->originResolution = NULL;
    }

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", parser->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int gai_ret = 0;
    if (parser->address_type == ATYP_IPV4) {
        printf("[DEBUG] ADDR_RESOLVE: Resolviendo IPv4 directa\n");
        // Para IPv4, crear la dirección directamente
        char ipv4_str[INET_ADDRSTRLEN];
        snprintf(ipv4_str, sizeof(ipv4_str), "%d.%d.%d.%d", 
                parser->ipv4_addr[0], parser->ipv4_addr[1], 
                parser->ipv4_addr[2], parser->ipv4_addr[3]);
        printf("[DEBUG] ADDR_RESOLVE: IPv4: %s, Puerto: %s\n", ipv4_str, port_str);
        
        hints.ai_family = AF_INET;
        gai_ret = getaddrinfo(ipv4_str, port_str, &hints, &clientData->originResolution);
        
    } else if (parser->address_type == ATYP_IPV6) {
        printf("[DEBUG] ADDR_RESOLVE: Resolviendo IPv6 directa\n");
        // Para IPv6, crear la dirección directamente
        char ipv6_str[INET6_ADDRSTRLEN];
        snprintf(ipv6_str, sizeof(ipv6_str), 
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                parser->ipv6_addr[0], parser->ipv6_addr[1], parser->ipv6_addr[2], parser->ipv6_addr[3],
                parser->ipv6_addr[4], parser->ipv6_addr[5], parser->ipv6_addr[6], parser->ipv6_addr[7],
                parser->ipv6_addr[8], parser->ipv6_addr[9], parser->ipv6_addr[10], parser->ipv6_addr[11],
                parser->ipv6_addr[12], parser->ipv6_addr[13], parser->ipv6_addr[14], parser->ipv6_addr[15]);
        printf("[DEBUG] ADDR_RESOLVE: IPv6: %s, Puerto: %s\n", ipv6_str, port_str);
        
        hints.ai_family = AF_INET6;
        gai_ret = getaddrinfo(ipv6_str, port_str, &hints, &clientData->originResolution);
        
    } else if (parser->address_type == ATYP_DOMAIN) {
        printf("[DEBUG] ADDR_RESOLVE: Resolviendo dominio\n");
        // Dominio: resolver con getaddrinfo
        hints.ai_family = AF_UNSPEC;
        char domain[256];
        memcpy(domain, parser->domain, parser->domain_length);
        domain[parser->domain_length] = '\0';
        printf("[DEBUG] ADDR_RESOLVE: Dominio: %s, Puerto: %s\n", domain, port_str);
        gai_ret = getaddrinfo(domain, port_str, &hints, &clientData->originResolution);
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
    
    printf("[DEBUG] CONNECTING_INIT: Socket creado (fd=%d), intentando conectar\n", clientData->originFd);
    
    // Intentar conectar
    if (connect(clientData->originFd, ai->ai_addr, ai->ai_addrlen) < 0) {
        printf("[DEBUG] CONNECTING_INIT: Error conectando: %s\n", strerror(errno));
        close(clientData->originFd);
        clientData->originFd = -1;
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
    selector_set_interest(key->s, clientData->clientFd, OP_WRITE);
    
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
        ssize_t bytes_written = write(clientData->clientFd, write_ptr, bytes_to_write);
        
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
    selector_status ss = selector_register(key->s, clientData->originFd, &handler, OP_READ, clientData);
    if (ss != SELECTOR_SUCCESS) {
        printf("[ERROR] COPYING_INIT: Error registrando socket del servidor de origen\n");
        return;
    }
    
    // Registrar el socket del cliente para lectura
    printf("[DEBUG] COPYING_INIT: Configurando socket del cliente (fd=%d) para lectura\n", clientData->clientFd);
    selector_set_interest(key->s, clientData->clientFd, OP_READ);
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
        ssize_t bytes_read = read(clientData->clientFd, write_ptr, bytes_to_write);
        
        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Cliente cerró conexión\n");
            return CLOSED;
        }
        stats_add_client_bytes(bytes_read);

        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del cliente\n", bytes_read);
        buffer_write_adv(&clientData->originBuffer, bytes_read);
        
        // Cambiar a escritura en el socket de origen
        printf("[DEBUG] COPYING_READ: Configurando socket del servidor para escritura\n");
        selector_set_interest(key->s, clientData->originFd, OP_WRITE);
        return COPYING;
        
    } else if (key->fd == clientData->originFd) {
        // Datos del servidor de origen -> cliente
        printf("[DEBUG] COPYING_READ: Leyendo datos del servidor\n");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->clientBuffer, &bytes_to_write);
        ssize_t bytes_read = read(clientData->originFd, write_ptr, bytes_to_write);
        
        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Servidor cerró conexión\n");
            return CLOSED;
        }
        
        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del servidor\n", bytes_read);
        buffer_write_adv(&clientData->clientBuffer, bytes_read);
        
        // Cambiar a escritura en el socket del cliente
        printf("[DEBUG] COPYING_READ: Configurando socket del cliente para escritura\n");
        selector_set_interest(key->s, clientData->clientFd, OP_WRITE);
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
            ssize_t bytes_written = write(clientData->clientFd, read_ptr, bytes_to_write);
            
            if (bytes_written < 0) {
                return ERROR;
            }
            
            buffer_read_adv(&clientData->clientBuffer, bytes_written);
            
            if (buffer_can_read(&clientData->clientBuffer)) {
                return COPYING;
            }
        }
        
        // Cambiar a lectura en el socket del cliente
        selector_set_interest(key->s, clientData->clientFd, OP_READ);
        return COPYING;
        
    } else if (key->fd == clientData->originFd) {
        // Escribir datos del buffer del origen al servidor de origen
        if (buffer_can_read(&clientData->originBuffer)) {
            size_t bytes_to_write;
            uint8_t *read_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
            ssize_t bytes_written = write(clientData->originFd, read_ptr, bytes_to_write);
            
            if (bytes_written < 0) {
                return ERROR;
            }
            
            buffer_read_adv(&clientData->originBuffer, bytes_written);
            
            if (buffer_can_read(&clientData->originBuffer)) {
                return COPYING;
            }
        }
        
        // Cambiar a lectura en el socket del servidor de origen
        selector_set_interest(key->s, clientData->originFd, OP_READ);
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
}

void errorArrival(const unsigned state, struct selector_key *key) {
    printf("Llegando al estado ERROR\n");
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
