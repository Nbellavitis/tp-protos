#include "negotiationParser.h"
#include "../Statistics/statistics.h"

#define VERSION_5 0x05


negotiation_parse negotiationParse(negotiation_parser *p, struct buffer *b) {
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        if (p->version == 0) {
            p->version = byte;
            if (p->version != VERSION_5) {
                p->error = true;
                return NEGOTIATION_PARSE_ERROR;
            }
        } else if (p->nmethods == 0) {
            p->nmethods = byte;
            if (p->nmethods == 0 /*|| p->nmethods > 255*/ /*nunca pasa por el tipo de dato*/) { // maximo por rfc
                p->error = true;
                return NEGOTIATION_PARSE_ERROR;
            }
        } else {
            if (p->i < p->nmethods) {
                p->methods[p->i++] = byte;
            }

            if (p->i == p->nmethods) {
                p->method_chosen = 0xFF;
                // Preferir sin autenticación (0x00) si está disponible
                for (int i = 0; i < p->nmethods; i++) {
                    if (p->methods[i] == 0x00) { // no auth
                        p->method_chosen = 0x00;
                        break;
                    }
                }
                // Si no está 0x00, buscar autenticación (0x02)
                if (p->method_chosen == 0xFF) {
                    for (int i = 0; i < p->nmethods; i++) {
                        if (p->methods[i] == 0x02) { // auth
                            p->method_chosen = 0x02;
                            break;
                        }
                    }
                }
                return NEGOTIATION_PARSE_OK;
            }
        }
    }
    return NEGOTIATION_PARSE_INCOMPLETE;
}


void initNegotiationParser(negotiation_parser *parser){
    parser->version = 0;
    parser->nmethods = 0;
    parser->method_chosen = 0x02; //default pass y user
    parser->i = 0;
}

bool sendNegotiationResponse(struct buffer *originBuffer, uint8_t method) {
    if (!buffer_can_write(originBuffer)) {
        return false;
    }
    buffer_write(originBuffer, VERSION_5); // versión
    buffer_write(originBuffer, method); // método elegido
    stats_add_origin_bytes(2);

    return true;
}