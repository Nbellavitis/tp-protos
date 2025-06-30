#include "negotiation.h"
#include "negotiationParser.h"
#include <errno.h>
#define VERSION_5 0x05
void negotiationReadInit(unsigned state, struct selector_key *key) {
    printf("Inicio negociación\n");
    struct ClientData *data = (struct ClientData *)key->data;
    initNegotiationParser(&data->client.negParser);

}
unsigned negotiationRead(struct selector_key *key) {
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    size_t readLimit;
    size_t readCount;
    uint8_t *b = buffer_write_ptr(&data->clientBuffer,&readLimit);
    if (readLimit == 0) {
        // Buffer full, compact and try again
        buffer_compact(&data->clientBuffer);
        b = buffer_write_ptr(&data->clientBuffer,&readLimit);
        if (readLimit == 0) {
            printf("[ERROR 019] negotiationRead: Buffer sin espacio después de compactar - fd:%d\n", key->fd);
            return ERROR;
        }
    }
    readCount=recv(key->fd,b,readLimit,0);
    if (readCount <= 0) {
        if (readCount == 0) {
            printf("[DEBUG] negotiationRead: Cliente cerró conexión - fd:%d\n", key->fd);
        } else {
            printf("[ERROR 020] negotiationRead: Error en recv() - fd:%d, errno:%d\n", key->fd, errno);
        }
        return ERROR;
    }
    stats_add_client_bytes(readCount);  //@todo checkear todos los lugares donde poner esto

    buffer_write_adv(&data->clientBuffer, readCount);
    negotiation_parse result = negotiationParse(p, &data->clientBuffer);
    printf("Resultado de negociación: %d\n", result);
    switch (result) {
    case NEGOTIATION_PARSE_OK:
        if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || !sendNegotiationResponse(&data->originBuffer, p->method_chosen)) {
            return ERROR;
        }
        return NEGOTIATION_WRITE;
    case NEGOTIATION_PARSE_INCOMPLETE:
        return NEGOTIATION_READ;

    case NEGOTIATION_PARSE_ERROR:
    default:
        printf("[ERROR 021] negotiationRead: Error parseando negociación SOCKS5 - fd:%d\n", key->fd);
        p->method_chosen = 0xFF;
        return ERROR;
    }
}

unsigned negotiationWrite(struct selector_key *key) {
    printf("Escribiendo respuesta de negociación\n");
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    size_t writeLimit;
    size_t writeCount;
    uint8_t * b = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, b, writeLimit, MSG_NOSIGNAL );
    if (writeCount <= 0) {
        printf("[ERROR 022] negotiationWrite: Error en send() - fd:%d, errno:%d\n", key->fd, errno);
        return ERROR;
    }
    buffer_read_adv(&data->originBuffer, writeCount);
    stats_add_origin_bytes(writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    if (p->error) {
        printf("[ERROR 023] negotiationWrite: Parser en estado error - fd:%d\n", key->fd);
        return ERROR;
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        printf("[ERROR 024] negotiationWrite: Error configurando selector para lectura - fd:%d\n", key->fd);
        return ERROR;
    }
    printf("Negociación exitosa, método elegido: %d\n", p->method_chosen);
    
    if (p->method_chosen == 0x00) {
        printf("[DEBUG] NEGOTIATION_WRITE: Avanzando a REQ_READ (sin autenticación)\n");
        return REQ_READ;
    } else {
        printf("[DEBUG] NEGOTIATION_WRITE: Avanzando a AUTHENTICATION_READ (con autenticación)\n");
        return AUTHENTICATION_READ;
    }
}

