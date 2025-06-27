//
// Created by nicke on 25/6/2025.
//

#ifndef PROTOS_AUTHPARSER_H
#define PROTOS_AUTHPARSER_H
#include <stdint.h>
#include "../buffer.h"
#include "../Logging/statistics.h"
typedef enum {
    AUTH_PARSE_INCOMPLETE,  // faltan bytes, seguí esperando
    AUTH_PARSE_OK,          // parseo exitoso
    AUTH_PARSE_ERROR        // error de protocolo (versión inválida, datos inconsistentes)
} auth_parse;
typedef struct auth_parser {
    uint8_t version;
    uint8_t nameLength;
    char name[256];
    uint8_t passwordLength;
    char password[256];
    uint8_t offsetName;
    uint8_t offsetPassword;
    bool error;
} auth_parser;

void initAuthParser(auth_parser *parser);
bool sendAuthResponse(struct buffer *originBuffer, uint8_t version, uint8_t status);
unsigned authParse(auth_parser *p, struct buffer *b);

#endif //PROTOS_AUTHPARSER_H
