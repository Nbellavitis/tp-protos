#ifndef PROTOS_AUTHPARSER_H
#define PROTOS_AUTHPARSER_H
#include <stdint.h>
#include "../buffer.h"
#include "../Statistics/statistics.h"
#include "../protocol_constants.h"

#define AUTH_NAME_SIZE          256
#define AUTH_PASS_SIZE          256

typedef enum {
    AUTH_PARSE_INCOMPLETE,
    AUTH_PARSE_OK,
    AUTH_PARSE_ERROR
} auth_parse_result;
typedef struct auth_parser {
    uint8_t version;
    uint8_t name_length;
    char name[AUTH_NAME_SIZE];
    uint8_t password_length;
    char password[AUTH_PASS_SIZE];
    uint8_t offset_name;
    uint8_t offset_password;
    bool error;
} auth_parser;

void init_auth_parser(auth_parser *parser);
bool send_auth_response(struct buffer *origin_buffer, uint8_t version, uint8_t status);
auth_parse_result auth_parse(auth_parser *p, struct buffer *b);

#endif
