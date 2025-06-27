#include "authParser.h"
#include <string.h>
#include <stdio.h>
#include "../parser.h"

// Acciones simples que solo cargan el event:

static void version_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 0;
    ret->data[0] = c;
    ret->n = 1;
}

static void name_len_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 1;
    ret->data[0] = c;
    ret->n = 1;
}

static void name_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 2;
    ret->data[0] = c;
    ret->n = 1;
}

static void pass_len_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 3;
    ret->data[0] = c;
    ret->n = 1;
}

static void pass_read(struct parser_event *ret, const uint8_t c) {
    ret->type = 4;
    ret->data[0] = c;
    ret->n = 1;
}

// Transiciones por estado:

static const struct parser_state_transition version_transitions[] = {
        { .when = ANY, .dest = AUTH_NAME_LEN, .act1 = version_read }
};

static const struct parser_state_transition name_len_transitions[] = {
        { .when = ANY, .dest = AUTH_NAME, .act1 = name_len_read }
};

static const struct parser_state_transition name_transitions[] = {
        { .when = ANY, .dest = AUTH_NAME, .act1 = name_read }
};

static const struct parser_state_transition pass_len_transitions[] = {
        { .when = ANY, .dest = AUTH_PASS, .act1 = pass_len_read }

};

static const struct parser_state_transition pass_transitions[] = {
        { .when = ANY, .dest = AUTH_PASS, .act1 = pass_read }
};

static const struct parser_state_transition *states[] = {
        version_transitions,
        name_len_transitions,
        name_transitions,
        pass_len_transitions,
        pass_transitions,
};

static const size_t states_n[] = {
        1,
        1,
        1,
        1,
        1
};

static const struct parser_definition auth_def = {
        .states_count = 5,
        .states = states,
        .states_n = states_n,
        .start_state = AUTH_VERSION
};

void initAuthParser(auth_parser *p) {
    memset(p, 0, sizeof(*p));
    p->parser = parser_init(parser_no_classes(), &auth_def);
    p->done = false;
    p->error = false;
}

auth_parse authParse(auth_parser *p, struct buffer *b) {
    while (buffer_can_read(b) && !p->done && !p->error) {
        uint8_t c = buffer_read(b);
        const struct parser_event *event = parser_feed(p->parser, c);

        if (event->n != 1) continue;

        switch (event->type) {
            case 0:  // Version
                p->version = event->data[0];
                if (p->version != 0x01) {
                    p->error = true;
                    printf("Error: Invalid version %d\n", p->version);
                    return AUTH_PARSE_ERROR;
                }
                break;

            case 1:  // Name length
                p->nameLength = event->data[0];
                if (p->nameLength == 0 || p->nameLength > 255) {
                    p->error = true;
                    printf("Error: Invalid name length %d\n", p->nameLength);
                    return AUTH_PARSE_ERROR;
                }
                p->offsetName = 0;
                break;

            case 2:  // Name bytes
                if (p->offsetName < p->nameLength) {
                    p->name[p->offsetName++] = event->data[0];
                    if (p->offsetName == p->nameLength) {
                        p->name[p->offsetName] = '\0';
                        change_state(p->parser, AUTH_PASS_LEN);  // Change to password length state
                    }
                }
                break;

            case 3:  // Password length
                p->passwordLength = event->data[0];
                if (p->passwordLength == 0 || p->passwordLength > 255) {
                    p->error = true;
                    printf("Error: Invalid password length %d\n", p->passwordLength);
                    return AUTH_PARSE_ERROR;
                }
                p->offsetPassword = 0;
                break;

            case 4:  // Password bytes
                if (p->offsetPassword < p->passwordLength) {
                    p->password[p->offsetPassword++] = event->data[0];
                    if (p->offsetPassword == p->passwordLength) {
                        p->password[p->offsetPassword] = '\0';
                        p->done = true;
                        return AUTH_PARSE_OK;
                    }
                }
                break;
        }
    }

    if (p->error) {
        return AUTH_PARSE_ERROR;
    } else if (p->done) {
        return AUTH_PARSE_OK;
    } else {
        return AUTH_PARSE_INCOMPLETE;
    }
}

bool sendAuthResponse(struct buffer *originBuffer, uint8_t version, uint8_t status) {
    if (!buffer_can_write(originBuffer)) {
        return false;
    }
    buffer_write(originBuffer, version);
    buffer_write(originBuffer, status);
    return true;
}
