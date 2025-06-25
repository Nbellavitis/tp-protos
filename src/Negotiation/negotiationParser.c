#include "negotiationParser.h"
#define VERSION_5 0x05


negotiation_parse negotiationParse(negotiation_parser *p, struct buffer *b) {
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        if (p->version == 0) {
            p->version = byte;
            if (p->version != VERSION_5) {
                return NEGOTIATION_PARSE_ERROR;
            }
        } else if (p->nmethods == 0) {
            p->nmethods = byte;
            if (p->nmethods == 0 || p->nmethods > 255) { // maximo por rfc
                return NEGOTIATION_PARSE_ERROR;
            }
        } else {
            if (p->i < p->nmethods) {
                p->methods[p->i++] = byte;
            }

            if (p->i == p->nmethods) {
                p->method_chosen = 0xFF;
                for (int i = 0; i < p->nmethods; i++) {
                    if (p->methods[i] == 0x00) { // sin autenticación
                        p->method_chosen = 0x00;
                        break;
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
    parser->method_chosen = 0xFF;  // Por defecto, ninguno elegido
    parser->i = 0;
}