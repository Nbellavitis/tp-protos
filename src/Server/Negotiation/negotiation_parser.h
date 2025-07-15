
#ifndef NEGOTITATIONPARSER_H
#define NEGOTITATIONPARSER_H
#include <stdint.h>
#include "../buffer.h"
#include <stdio.h>
#include "../selector.h"
#include "../protocol_constants.h"


#define MAX_AUTH_METHODS 255

typedef enum {
    NEGOTIATION_PARSE_INCOMPLETE,
    NEGOTIATION_PARSE_OK,
    NEGOTIATION_PARSE_ERROR
} negotiation_parse_result;


typedef struct negotiation_parser {
    struct parser *parser;
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[MAX_AUTH_METHODS];
    uint8_t method_chosen;
    uint8_t i;
    bool error;
} negotiation_parser;
void  init_negotiation_parser(negotiation_parser *parser);
negotiation_parse_result negotiation_parse(negotiation_parser *p, struct buffer* buffer);
bool send_negotiation_response(struct buffer *origin_buffer, uint8_t method);
void set_auth_method(uint8_t method);
uint8_t get_auth_method();
#endif
