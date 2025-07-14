#include "negotiationParser.h"
#include "../Statistics/statistics.h"

#include "../protocol_constants.h"

static uint8_t authMethod = USERPASS;

negotiation_parse negotiationParse(negotiation_parser *p, struct buffer *b) {
    while (buffer_can_read(b)) {
        const uint8_t byte = buffer_read(b);
        if (p->version == 0) {
            p->version = byte;
            if (p->version != SOCKS5_VERSION) {
                p->error = true;
                return NEGOTIATION_PARSE_ERROR;
            }
        } else if (p->nmethods == 0) {
            p->nmethods = byte;
            if (p->nmethods == 0) {
                p->error = true;
                return NEGOTIATION_PARSE_ERROR;
            }
        } else {
            if (p->i < p->nmethods) {
                p->methods[p->i++] = byte;
            }

            if (p->i == p->nmethods) {
                p->method_chosen = NO_ACCEPTABLE_METHODS;

                for (int i = 0; i < p->nmethods; i++) {
                    if (p->methods[i] == USERPASS) {
                        p->method_chosen = USERPASS;
                        break;
                    }
                }

                if (p->method_chosen == NO_ACCEPTABLE_METHODS) {
                    for (int i = 0; i < p->nmethods; i++) {
                        if (p->methods[i] == NOAUTH && getAuthMethod() != USERPASS) {
                            p->method_chosen = NOAUTH;
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
    parser->method_chosen = authMethod; //default pass y user
    parser->i = 0;
}

bool sendNegotiationResponse(struct buffer *originBuffer, uint8_t method) {
    if (!buffer_can_write(originBuffer)) {
        return false;
    }
    buffer_write(originBuffer, SOCKS5_VERSION);
    buffer_write(originBuffer, method);
    stats_add_origin_bytes(2); // 1 byte SOCKS5_VERSION + 1 byte method

    return true;
}
void setAuthMethod(uint8_t method) {
     if (method == NOAUTH || method == USERPASS) {
         authMethod = method;
     } else {
         LOG_ERROR("Invalid authentication method: %d", method);
     }
}
uint8_t getAuthMethod() {
    return authMethod;
}