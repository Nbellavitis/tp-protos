#ifndef PROTOS_AUTHPARSER_H
#define PROTOS_AUTHPARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "../buffer.h"
#include "../parser.h"

typedef enum {
    AUTH_PARSE_INCOMPLETE,
    AUTH_PARSE_OK,
    AUTH_PARSE_ERROR
} auth_parse;

typedef enum {
    AUTH_VERSION,
    AUTH_NAME_LEN,
    AUTH_NAME,
    AUTH_PASS_LEN,
    AUTH_PASS,
    AUTH_DONE
} auth_states;

typedef struct auth_parser {
    struct parser *parser;
    uint8_t version;
    uint8_t nameLength;
    char name[256];
    uint8_t passwordLength;
    char password[256];
    uint8_t offsetName;
    uint8_t offsetPassword;
    bool error;
    bool done;
} auth_parser;

void initAuthParser(auth_parser *p);
auth_parse authParse(auth_parser *p, struct buffer *b);
bool sendAuthResponse(struct buffer *originBuffer, uint8_t version, uint8_t status);

#endif // PROTOS_AUTHPARSER_H
