//
// Created by nicke on 26/6/2025.
//

#ifndef PROTOS_RESOLVERPARSER_H
#define PROTOS_RESOLVERPARSER_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../buffer.h"
#include <arpa/inet.h>

// SOCKS5 protocol constants
#define IPV6_ADDR_SIZE          16
#define MAX_DOMAIN_LEN          256
#define MAX_SOCKS5_DOMAIN_LEN   255  // RFC 1928: domain length is limited to 255 bytes
typedef enum {
    REQUEST_PARSE_INCOMPLETE,  // faltan bytes, seguí esperando
    REQUEST_PARSE_OK,          // parseo exitoso
    REQUEST_PARSE_ERROR        // error de protocolo
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
    
    // Para IPv4
    uint8_t ipv4_addr[4];
    
    // Para IPv6
    uint8_t ipv6_addr[IPV6_ADDR_SIZE];
    
    // Para dominio
    uint8_t domain_length;
    char domain[MAX_DOMAIN_LEN];
    
    uint16_t port;
    
    // Estado del parsing
    uint8_t state;
    uint8_t bytes_read;
    bool done;
    bool error;
} resolver_parser;

void initResolverParser(resolver_parser *parser);
request_parse resolverParse(resolver_parser *p, struct buffer *buffer);
bool prepareRequestResponse(struct buffer *originBuffer, uint8_t version, uint8_t reply, uint8_t atyp, const void *bnd_addr, uint16_t bnd_port);

#endif //PROTOS_RESOLVERPARSER_H
