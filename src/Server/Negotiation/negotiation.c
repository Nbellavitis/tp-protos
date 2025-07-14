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
    uint8_t *b = buffer_write_ptr(&data->clientBuffer,&readLimit);
    const ssize_t readCount = recv(key->fd, b, readLimit, 0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    stats_add_client_bytes(readCount);  //@todo checkear todos los lugares donde poner esto

    buffer_write_adv(&data->clientBuffer, readCount);
    negotiation_parse result = negotiationParse(p, &data->clientBuffer);
    LOG_DEBUG("NEGOTIATION_READ: Negotiation result: %d", result);

    if (result == NEGOTIATION_PARSE_INCOMPLETE) {
        return NEGOTIATION_READ;
    }

    if (result != NEGOTIATION_PARSE_OK) {
        p->method_chosen = 0xFF;
        return ERROR;
    }

    if (!sendNegotiationResponse(&data->originBuffer, p->method_chosen)) {
        return ERROR;
    }

    return negotiationWrite(key);
}

void negotiationWriteInit(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("NEGOTIATION_WRITE_INIT: Setting interest to OP_WRITE");
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        closeConnection(key); // Es un error crítico, no podemos continuar.
    }
}

unsigned negotiationWrite(struct selector_key *key) {
    LOG_DEBUG("%s" ,"NEGOTIATION_WRITE: Writing negotiation response");
    ClientData *data = key->data;

    ssize_t bytes_written;
    if (!buffer_flush(&data->originBuffer, key->fd, &bytes_written)) {
        return ERROR;
    }

    stats_add_origin_bytes(bytes_written);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    negotiation_parser *p = &data->client.negParser;
    // todo, podríamos llegar hasta acá y que p->method_chose sea igual a 0xFF??
    if (p->method_chosen == 0xFF) {
        return ERROR;
    }

    if (p->method_chosen == NOAUTH ) {
        return REQ_READ;
    }

    return AUTHENTICATION_READ;

}