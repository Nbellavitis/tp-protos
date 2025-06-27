#include "negotiationParser.h"
#include <string.h>

#define VERSION_5 0x05

enum negotiation_states {
    NEG_VERSION,
    NEG_NMETHODS,
    NEG_METHODS,
    NEG_DONE,
    NEG_ERROR
};

static void version_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 0;
    ret->data[0] = c;
    ret->n = 1;
}

static void nmethods_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 1;
    ret->data[0] = c;
    ret->n = 1;
}

static void method_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 2;
    ret->data[0] = c;
    ret->n = 1;
}

static const struct parser_state_transition version_transitions[] = {
        { .when = ANY, .dest = NEG_NMETHODS, .act1 = version_read }
};

static const struct parser_state_transition nmethods_transitions[] = {
        { .when = ANY, .dest = NEG_METHODS, .act1 = nmethods_read }
};

static const struct parser_state_transition methods_transitions[] = {
        { .when = ANY, .dest = NEG_METHODS, .act1 = method_read }
};

static const struct parser_state_transition *states[] = {
        version_transitions,
        nmethods_transitions,
        methods_transitions,
};

static const size_t states_n[] = {
        1, 1, 1
};

static const struct parser_definition negotiation_def = {
        .states_count = 3,
        .states = states,
        .states_n = states_n,
        .start_state = NEG_VERSION
};

void initNegotiationParser(negotiation_parser *p) {
    memset(p, 0, sizeof(*p));
    p->parser = parser_init(parser_no_classes(), &negotiation_def);
    p->method_chosen = 0x02;
}

negotiation_parse negotiationParse(negotiation_parser *p, struct buffer *b) {
    while (buffer_can_read(b) && !p->done && !p->error) {
        uint8_t byte = buffer_read(b);
        const struct parser_event *event = parser_feed(p->parser, byte);

        if (event->n == 1) {
            switch (event->type) {
                case 0:  // version
                    p->version = event->data[0];
                    if (p->version != VERSION_5) {
                        p->error = true;
                        return NEGOTIATION_PARSE_ERROR;
                    }
                    break;

                case 1:  // nmethods
                    p->nmethods = event->data[0];
                    if (p->nmethods == 0 || p->nmethods > 255) {
                        p->error = true;
                        return NEGOTIATION_PARSE_ERROR;
                    }
                    break;

                case 2:  // methods
                    if (p->i < p->nmethods) {
                        p->methods[p->i++] = event->data[0];
                    }
                    if (p->i == p->nmethods) {
                        // Selección de método
                        p->method_chosen = 0xFF;
                        for (int i = 0; i < p->nmethods; i++) {
                            if (p->methods[i] == 0x02) {
                                p->method_chosen = 0x02;
                                break;
                            }
                            if (p->methods[i] == 0x00) {
                                p->method_chosen = 0x00;
                            }
                        }
                        p->done = true;
                        return NEGOTIATION_PARSE_OK;
                    }
                    break;

                default:
                    break;
            }
        }
    }

    if (p->error) {
        return NEGOTIATION_PARSE_ERROR;
    } else if (p->done) {
        return NEGOTIATION_PARSE_OK;
    } else {
        return NEGOTIATION_PARSE_INCOMPLETE;
    }
}

bool sendNegotiationResponse(struct buffer *originBuffer, uint8_t method) {
    if (!buffer_can_write(originBuffer)) {
        return false;
    }
    buffer_write(originBuffer, VERSION_5); // versión
    buffer_write(originBuffer, method); // método elegido
    return true;
}