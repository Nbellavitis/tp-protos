#ifndef REQUESTPARSER_H
#define REQUESTPARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "../buffer.h"

typedef enum {
    REQUEST_PARSE_INCOMPLETE,
    REQUEST_PARSE_OK,
    REQUEST_PARSE_ERROR
} request_parse;

typedef struct request_parser {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    uint8_t dest_addr[256];
    char    dest_addr_str[256];
    uint16_t dest_port;
    uint8_t addr_len;
    uint8_t bytes_read;
    bool    reading_port;
    bool    rsv_read;
    bool    port_hi_read;
    uint8_t reply_code;
    bool    error;
} request_parser;

void initRequestParser(request_parser *p);
request_parse requestParse(request_parser *p, struct buffer *b);
bool sendRequestResponse(struct buffer *out, uint8_t version, uint8_t reply);

#endif
