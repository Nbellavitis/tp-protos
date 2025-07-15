#include <stdio.h>
#include "auth_parser.h"
#include "../../logger.h"


void init_auth_parser(auth_parser *parser) {
    parser->version = 0;
    parser->name_length = 0;
    parser->password_length = 0;
    parser->name[0] = '\0';
    parser->password[0] = '\0';
    parser->offset_name = 0;
    parser->offset_password = 0;
}



auth_parse_result auth_parse(auth_parser *p, struct buffer *b) {
    while (buffer_can_read(b)){
        uint8_t byte = buffer_read(b);
        if(p->version == 0){
            if(byte != AUTH_VERSION){
                p->error = true;
                return AUTH_PARSE_ERROR;
            }
            p->version = byte;
        }else if(p->name_length == 0){
                if(byte == 0){
                    p->error = true;
                    return AUTH_PARSE_ERROR;
                }
                p->name_length = byte;
        }else if(p->offset_name < p->name_length) {

            p->name[p->offset_name++] = byte;
            if (p->offset_name == p->name_length) {
                p->name[p->offset_name] = '\0';
            }
        }else if (p->password_length == 0) {
            if (byte == 0) {
                p->error = true;
                return AUTH_PARSE_ERROR;
            }
            p->password_length = byte;
        } else if (p->offset_password < p->password_length) {
            p->password[p->offset_password++] = byte;
            if (p->offset_password == p->password_length) {
                p->password[p->offset_password] = '\0';
                return AUTH_PARSE_OK;
            }
        }
    }
    return AUTH_PARSE_INCOMPLETE;
}

bool send_auth_response(struct buffer *origin_buffer, uint8_t version, uint8_t status) {
    if (!buffer_can_write(origin_buffer)) {
        return false;
    }
    buffer_write(origin_buffer, version);
    buffer_write(origin_buffer, status);

    stats_add_origin_bytes(2);
    return true;
}