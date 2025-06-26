#include "negotiation.h"
#include "negotiationParser.h"
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
    readCount=recv(key->fd,b,readLimit,0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
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
        return ERROR; // error o desconexión
    }
    buffer_read_adv(&data->originBuffer, writeCount);

    if (buffer_can_read(&data->originBuffer)) {
        return NEGOTIATION_WRITE;
    }

    if (p->error || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
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

