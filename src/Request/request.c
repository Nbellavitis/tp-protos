#include "request.h"
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include "requestParser.h"
#include "helper.h"

void requestReadInit(unsigned state, struct selector_key *key) {
    printf("Inicio lectura de request\n");
    struct ClientData *data = (struct ClientData *)key->data;
    initRequestParser(&data->client.reqParser);
}



unsigned requestRead(struct selector_key *key) {
    ClientData *data = key->data;
    request_parser *p = &data->client.reqParser;

    size_t readLimit;
    size_t readCount;
    uint8_t *b = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, b, readLimit, 0);

    if (readCount <= 0) {
        return ERROR;
    }

    buffer_write_adv(&data->clientBuffer, readCount);
    request_parse result = requestParse(p, &data->clientBuffer);

    switch (result) {
        case REQUEST_PARSE_OK:
            printf("Request parseado: cmd=%d, atyp=%d, addr=%s, port=%d\n",
                   p->cmd, p->atyp, p->dest_addr_str, p->dest_port);

            // Solo soportamos CONNECT (0x01)
            if (p->cmd != 0x01) {
                sendRequestResponse(&data->originBuffer, 0x05, 0x07); // Command not supported
                if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                    return ERROR;
                }
                return REQ_WRITE;
            }

            // Si es dominio, necesitamos resolver DNS
            if (p->atyp == 0x03) {
                // TODO: Implementar resolución DNS asíncrona
                // Por ahora simulamos que ya está resuelto
                struct addrinfo hints = {
                    .ai_family = AF_UNSPEC,
                    .ai_socktype = SOCK_STREAM,
                    .ai_flags = AI_PASSIVE,
                    .ai_protocol = 0,
                    .ai_canonname = NULL,
                    .ai_addr = NULL,
                    .ai_next = NULL,
                };

                char port_str[6];
                snprintf(port_str, sizeof(port_str), "%d", p->dest_port);

                if (getaddrinfo(p->dest_addr_str, port_str, &hints, &data->originResolution) != 0) {
                    sendRequestResponse(&data->originBuffer, 0x05, 0x04); // Host unreachable
                    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                        return ERROR;
                    }
                    return REQ_WRITE;
                }

                return CONNECTING;
            } else {
                // IPv4 o IPv6, crear estructura directamente
                return CONNECTING;
            }

        case REQUEST_PARSE_INCOMPLETE:
            return REQ_READ;

        case REQUEST_PARSE_ERROR:
        default:
            return ERROR;
    }
}

void requestConnectingInit(unsigned state, struct selector_key *key) {
    ClientData *data = key->data;
    request_parser *p = &data->client.reqParser;

    // Crear socket para conectar al origen
    int domain = (p->atyp == 0x04) ? AF_INET6 : AF_INET;
    data->originFd = socket(domain, SOCK_STREAM, IPPROTO_TCP);

    if (data->originFd < 0) {
        sendRequestResponse(&data->originBuffer, 0x05, 0x01); // General failure
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // Configurar non-blocking
    if (selector_fd_set_nio(data->originFd) == -1) {
        close(data->originFd);
        data->originFd = -1;
        sendRequestResponse(&data->originBuffer, 0x05, 0x01);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // Registrar el fd del origen en el selector
    if (registerOriginSocket(key, data->originFd, data) != SELECTOR_SUCCESS) {
        close(data->originFd);
        data->originFd = -1;
        sendRequestResponse(&data->originBuffer, 0x05, 0x01);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    // Intentar conectar
    struct sockaddr_storage addr;
    socklen_t addr_len;

    if (p->atyp == 0x01) { // IPv4
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(p->dest_port);
        memcpy(&addr4->sin_addr, p->dest_addr, 4);
        addr_len = sizeof(struct sockaddr_in);
    } else if (p->atyp == 0x04) { // IPv6
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(p->dest_port);
        memcpy(&addr6->sin6_addr, p->dest_addr, 16);
        addr_len = sizeof(struct sockaddr_in6);
    } else if (data->originResolution) { // Dominio ya resuelto
        addr_len = data->originResolution->ai_addrlen;
        memcpy(&addr, data->originResolution->ai_addr, addr_len);
    }

    if (connect(data->originFd, (struct sockaddr *)&addr, addr_len) == -1) {
        if (errno == EINPROGRESS) {
            // Conexión en progreso, esperamos a que esté lista para escribir
            selector_set_interest(key->s, data->originFd, OP_WRITE);
        } else {
            // Error real
            sendRequestResponse(&data->originBuffer, 0x05, 0x05); // Connection refused
            selector_set_interest_key(key, OP_WRITE);
        }
    } else {
        // Conexión inmediata (raro pero posible)
        sendRequestResponse(&data->originBuffer, 0x05, 0x00); // Success
        selector_set_interest_key(key, OP_WRITE);
    }
}

unsigned requestConnecting(struct selector_key *key) {
    ClientData *data = key->data;

    // Verificar si es el fd del origen
    if (key->fd == data->originFd) {
        // Verificar si la conexión se completó
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(data->originFd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            // Error en la conexión
            sendRequestResponse(&data->originBuffer, 0x05, 0x05); // Connection refused
            selector_set_interest(key->s, data->clientFd, OP_WRITE);
            selector_set_interest(key->s, data->originFd, OP_NOOP);
            return REQ_WRITE;
        }

        // Conexión exitosa
        sendRequestResponse(&data->originBuffer, 0x05, 0x00); // Success
        selector_set_interest(key->s, data->clientFd, OP_WRITE);
        selector_set_interest(key->s, data->originFd, OP_NOOP);
        return REQ_WRITE;
    }

    return CONNECTING;
}

unsigned requestWrite(struct selector_key *key) {
    ClientData *data = key->data;

    size_t writeLimit;
    size_t writeCount;
    uint8_t *b = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, b, writeLimit, MSG_NOSIGNAL);

    if (writeCount <= 0) {
        return ERROR;
    }

    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return REQ_WRITE;
    }

    // Si hubo error en la respuesta, cerramos
    request_parser *p = &data->client.reqParser;
    if (p->reply_code != 0x00) {
        return ERROR;
    }

    // Preparar para el estado COPYING
    selector_set_interest(key->s, data->clientFd, OP_READ);
    selector_set_interest(key->s, data->originFd, OP_READ);

    printf("Conexión establecida, iniciando COPYING\n");
    return COPYING;
}

// void addressResolveDone(unsigned state, struct selector_key *key) {
//     ClientData *data = key->data;
//
//     // Aquí deberías verificar el resultado de la resolución DNS
//     // Por ahora asumimos que ya está en data->originResolution
//
//     if (data->originResolution == NULL) {
//         sendRequestResponse(&data->originBuffer, 0x05, 0x04); // Host unreachable
//         selector_set_interest_key(key, OP_WRITE);
//         stm_handler_write(&data->stm, key); // Forzar transición a REQ_WRITE
//         return;
//     }
//
//     // Continuar con la conexión
//     stm_handler_write(&data->stm, key); // Transición a CONNECTING
// }

unsigned addressResolveDone(struct selector_key *key) {
    // Por ahora no implementada - el DNS se resuelve sincrónicamente
    return CONNECTING;
}