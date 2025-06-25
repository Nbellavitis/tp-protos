//
// Created by nicke on 25/6/2025.
//
#include "authParser.h"
void initAuthParser(auth_parser *parser) {
    parser->version = 0;
    parser->nameLength = 0;
    parser->passwordLength = 0;
    parser->name[0] = '\0';
    parser->password[0] = '\0';
    parser->offsetName = 0;
    parser->offsetPassword = 0;
}



unsigned authParse(auth_parser *p, struct buffer *b){
    while (buffer_can_read(b)){
        uint8_t byte = buffer_read(b);
        if(p->version == 0){
            if(byte !=0x05){
                return AUTH_PARSE_ERROR;
            }
            p->version = byte;
        }else if(p->nameLength == 0){
                if(byte > 255 || byte == 0){
                    return AUTH_PARSE_ERROR;
                }
                p->nameLength = byte;
        }else if(p->offsetName < p->nameLength) {
            p->name[p->offsetName++] = byte;
            if (p->offsetName == p->nameLength) {
                p->name[p->offsetName] = '\0'; // Null-terminate the name
            }
        }else if (p->passwordLength == 0) {
            if (byte > 255 || byte == 0) {
                return AUTH_PARSE_ERROR;
            }
            p->passwordLength = byte;
        } else if (p->offsetPassword < p->passwordLength) {
            p->password[p->offsetPassword++] = byte;
            if (p->offsetPassword == p->passwordLength) {
                p->password[p->offsetPassword] = '\0'; // Null-terminate the password
                return AUTH_PARSE_OK;
            }
        }
    }
    return AUTH_PARSE_INCOMPLETE;
}