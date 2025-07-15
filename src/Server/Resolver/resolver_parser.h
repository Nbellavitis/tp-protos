#ifndef PROTOS_RESOLVERPARSER_H
#define PROTOS_RESOLVERPARSER_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../buffer.h"
#include <arpa/inet.h>

#include "../constants.h"
#include "../protocol_constants.h"

#define RESOLVER_STATE_VERSION      0
#define RESOLVER_STATE_COMMAND      1
#define RESOLVER_STATE_RESERVED     2
#define RESOLVER_STATE_ATYP         3
#define RESOLVER_STATE_ADDRESS      4
#define RESOLVER_STATE_PORT         5

#define MAX_DOMAIN_LEN          256
#define MAX_SOCKS5_DOMAIN_LEN   255  // RFC 1928: domain length is limited to 255 bytes
typedef enum {
    REQUEST_PARSE_INCOMPLETE,
    REQUEST_PARSE_OK,
    REQUEST_PARSE_ERROR
} request_parse;

typedef enum {
    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,
    CMD_UDP_ASSOCIATE = 0x03
} request_command;

typedef enum {
    ATYP_IPV4 = 0x01,
    ATYP_DOMAIN = 0x03,
    ATYP_IPV6 = 0x04
} address_type;

typedef struct resolver_parser {
    uint8_t version;
    uint8_t command;
    uint8_t reserved;
    uint8_t address_type;
    
    uint8_t ipv4_addr[IPV4_ADDR_SIZE];
    
    uint8_t ipv6_addr[IPV6_ADDR_SIZE];
    
    uint8_t domain_length;
    char domain[MAX_DOMAIN_LEN];
    
    uint16_t port;
    
    uint8_t state;
    uint8_t bytes_read;
    bool done;
    bool error;
} resolver_parser;

void init_resolver_parser(resolver_parser *parser);
request_parse resolver_parse(resolver_parser *p, struct buffer *buffer);
bool prepare_request_response(struct buffer *origin_buffer, uint8_t version, uint8_t reply, uint8_t atyp, const void *bnd_addr, uint16_t bnd_port);

#endif
