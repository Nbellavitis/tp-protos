#include "auth.h"



void authenticationReadInit(struct selector_key * key){
    printf("Inicio autenticación\n");
    struct ClientData *data = (struct ClientData *)key->data;
    initAuthParser(&data->client.authParser);
}

unsigned authenticationRead(struct selector_key * key){
    ClientData *data = key->data;
    auth_parser *p = &data->client.authParser;
    buffer *b = &data->clientBuffer;
    auth_parse result = authParse(p, b);

    switch (result) {
        case AUTH_PARSE_OK:
            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return AUTHENTICATION_WRITE;

        case AUTH_PARSE_INCOMPLETE:
            return AUTHENTICATION_READ;

        case AUTH_PARSE_ERROR:
        default:
            return ERROR;
    }
}

unsigned authenticationWrite(struct selector_key * key){
    ClientData *data = key->data;
    auth_parser *p = &data->client.authParser;
    buffer *b = &data->clientBuffer;
    if (!buffer_can_write(b)) {
        return AUTHENTICATION_WRITE; // esperá espacio
    }
    buffer_write(b, p->version); // versión
//    if(aljghajkl) //logica de auth!!!
    buffer_write(b,0x00); //hardcodeado exito!!!!
    printf("Autenticación exitosa\n");
    return REQ_READ; // Continuar con la lectura de la solicitud
}