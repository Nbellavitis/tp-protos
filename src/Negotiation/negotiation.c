#include "negotiation.h"
#include "negotiationParser.h"
#define VERSION_5 0x05
void negotiationReadInit( struct selector_key *key) {
    printf("Inicio negociación\n");
    struct ClientData *data = (struct ClientData *)key->data;
    initNegotiationParser(&data->client.negParser);
}
unsigned negotiationRead(struct selector_key *key) {
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    buffer *b = &data->clientBuffer;
    negotiation_parse result = negotiationParse(p, b);
    switch (result) {
    case NEGOTIATION_PARSE_OK:
        if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
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
    ClientData *data = key->data;
    negotiation_parser *p = &data->client.negParser;
    buffer *b = &data->clientBuffer;
    if (!buffer_can_write(b)) {
        return NEGOTIATION_WRITE; // esperá espacio
    }
    buffer_write(b, VERSION_5);                 // versión
    buffer_write(b, p->method_chosen);     // método elegido
    if (p->method_chosen == 0xFF) {
        // cierro si es 0xFF, RFC DICE QUE HAGA ESTO!!!
        return ERROR;
    }
    return (p->method_chosen == 0x00) ? REQ_READ : AUTHENTICATION_READ;
}

