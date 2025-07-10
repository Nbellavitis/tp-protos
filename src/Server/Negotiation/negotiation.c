#include "negotiation.h"
#include "negotiationParser.h"
#include <errno.h>
#include "../../logger.h"
#define VERSION_5 0x05
void negotiationReadInit(unsigned state, struct selector_key *key) {
    LOG_DEBUG("NEGOTIATION_INIT: Starting negotiation (state = %d)", state);
    struct ClientData *data = (struct ClientData *)key->data;
    initNegotiationParser(&data->client.negParser);

}
unsigned negotiationRead(struct selector_key *key) {
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    size_t readLimit;
    size_t readCount;
    uint8_t *b = buffer_write_ptr(&data->clientBuffer,&readLimit);
    readCount=recv(key->fd,b,readLimit,0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    stats_add_client_bytes(readCount);  //@todo checkear todos los lugares donde poner esto

    buffer_write_adv(&data->clientBuffer, readCount);
    negotiation_parse result = negotiationParse(p, &data->clientBuffer);
    LOG_DEBUG("NEGOTIATION_READ: Negotiation result: %d", result);
    switch (result) {
        case NEGOTIATION_PARSE_OK:
            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || !sendNegotiationResponse(&data->originBuffer, p->method_chosen)) {
                return ERROR;
            }
            return negotiationWrite(key);
        case NEGOTIATION_PARSE_INCOMPLETE:
            return NEGOTIATION_READ;

        case NEGOTIATION_PARSE_ERROR:
        default:
            p->method_chosen = 0xFF;
            return ERROR;
    }
}

unsigned negotiationWrite(struct selector_key *key) {
    LOG_DEBUG("NEGOTIATION_WRITE: Writing negotiation response");
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    size_t writeLimit;
    size_t writeCount;
    uint8_t * b = buffer_read_ptr(&data->originBuffer, &writeLimit);
    writeCount = send(key->fd, b, writeLimit, MSG_NOSIGNAL );

    /*
    if (writeCount <= 0) {
        return ERROR; // error o desconexión
    }*/

    if (writeCount <= 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK)
               ? NEGOTIATION_WRITE
               : ERROR;
    }



    buffer_read_adv(&data->originBuffer, writeCount);
    stats_add_origin_bytes(writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    if (p->error || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    LOG_DEBUG("NEGOTIATION_WRITE: Successful negotiation, chosen method: %d", p->method_chosen);

    if (p->method_chosen == 0x00) {
        LOG_DEBUG("NEGOTIATION_WRITE: Advancing to REQ_READ (no authentication)");
        return REQ_READ;
    }
    // todo, revisar lo de abajo:
    if (p->method_chosen == 0xFF) {
        // Ya notificamos al cliente que ninguno de sus métodos es aceptado.
        // Ahora cerramos la conexión.
        return ERROR;
    }
    LOG_DEBUG("NEGOTIATION_WRITE: Advancing to AUTHENTICATION_READ (with authentication)");
    return AUTHENTICATION_READ;

}