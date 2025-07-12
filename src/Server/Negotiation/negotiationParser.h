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
#define NOAUTH 0x00
#define AUTH 0x02
typedef enum {
    NEGOTIATION_PARSE_INCOMPLETE,  // faltan bytes, seguí esperando
    NEGOTIATION_PARSE_OK,          // parseo exitoso, método elegido
    NEGOTIATION_PARSE_ERROR        // error de protocolo (versión inválida, datos inconsistentes)
} negotiation_parse;


typedef struct negotiation_parser {
    struct parser *parser;
    struct parser_definition def;
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[255];  // máximo según RFC
    uint8_t method_chosen;
    uint8_t i;             // cuántos métodos ya leyó
    bool done;
    bool error;
} negotiation_parser;
void  initNegotiationParser(negotiation_parser *parser);
negotiation_parse negotiationParse(negotiation_parser *p, struct buffer* buffer);
bool sendNegotiationResponse(struct buffer *originBuffer, uint8_t method);
void setAuthMethod(uint8_t method);
uint8_t getAuthMethod();
#endif //NEGOTITATIONPARSER_H
