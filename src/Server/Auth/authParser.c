//
// Created by nicke on 25/6/2025.
//
#include <stdio.h>
#include "authParser.h"
#include "../../logger.h"


void initAuthParser(auth_parser *parser) {
    parser->version = 0;
    parser->nameLength = 0;
    parser->passwordLength = 0;
    parser->name[0] = '\0';
    parser->password[0] = '\0';
    parser->offsetName = 0;
    parser->offsetPassword = 0;
}



unsigned authParse(auth_parser *p, struct buffer *b) {
    while (buffer_can_read(b)){
        uint8_t byte = buffer_read(b);
        if(p->version == 0){
            if(byte != AUTH_VERSION){
                p->error = true;
                LOG_ERROR("AUTH_PARSE: Invalid version %d", byte);
                return AUTH_PARSE_ERROR;
            }
            p->version = byte;
        }else if(p->nameLength == 0){
                if(byte == 0){
                    p->error = true;
                    LOG_ERROR("%s", "AUTH_PARSE: Invalid name length. Must be grater than 0.");
                    return AUTH_PARSE_ERROR;
                }
                p->nameLength = byte;
        }else if(p->offsetName < p->nameLength) {

            p->name[p->offsetName++] = byte;
            if (p->offsetName == p->nameLength) {
                p->name[p->offsetName] = '\0';
            }
        }else if (p->passwordLength == 0) {
            if (byte == 0) {
                p->error = true;
                LOG_ERROR("%s" ,"AUTH_PARSE: Invalid password length. Must be grater than 0");
                return AUTH_PARSE_ERROR;
            }
            p->passwordLength = byte;
        } else if (p->offsetPassword < p->passwordLength) {
            p->password[p->offsetPassword++] = byte;
            if (p->offsetPassword == p->passwordLength) {
                p->password[p->offsetPassword] = '\0';
                return AUTH_PARSE_OK;
            }
        }
    }
    return AUTH_PARSE_INCOMPLETE;
}

bool sendAuthResponse(struct buffer *originBuffer, uint8_t version, uint8_t status) {
    if (!buffer_can_write(originBuffer)) {
        return false;
    }
    buffer_write(originBuffer, version);
    buffer_write(originBuffer, status);

    stats_add_origin_bytes(2); // 1 byte version + 1 byte status
    return true;
}