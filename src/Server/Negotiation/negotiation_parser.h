//
// Created by nicke on 25/6/2025.
//

#ifndef NEGOTITATIONPARSER_H
#define NEGOTITATIONPARSER_H
#include <stdint.h>
#include "../parser.h"
#include "../buffer.h"
#include <stdio.h>
#include "../selector.h"
#include "../protocol_constants.h"


#define MAX_AUTH_METHODS 255  // máximo según RFC

typedef enum {
    NEGOTIATION_PARSE_INCOMPLETE,  // faltan bytes, seguí esperando
    NEGOTIATION_PARSE_OK,          // parseo exitoso, métodó elegido
    NEGOTIATION_PARSE_ERROR        // error de protocolo (versión inválida, datos inconsistentes)
} negotiation_parse_result;


typedef struct negotiation_parser {
    struct parser *parser;
    struct parser_definition def;
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[MAX_AUTH_METHODS];
    uint8_t method_chosen;
    uint8_t i;             // cuántos métodos ya leyó
    bool done;
    bool error;
} negotiation_parser;
void  init_negotiation_parser(negotiation_parser *parser);
negotiation_parse_result negotiation_parse(negotiation_parser *p, struct buffer* buffer);
bool send_negotiation_response(struct buffer *origin_buffer, uint8_t method);
void set_auth_method(uint8_t method);
uint8_t get_auth_method();
#endif //NEGOTITATIONPARSER_H
