#include "auth.h"



void authenticationReadInit(unsigned state,struct selector_key * key){
    printf("Inicio autenticación\n");
    struct ClientData *data = (struct ClientData *)key->data;
    initAuthParser(&data->client.authParser);
}

unsigned authenticationRead(struct selector_key * key){
    ClientData *data = key->data;
    printf("Leyendo autenticación\n");
    auth_parser *p = &data->client.authParser;
    size_t readLimit;
    size_t readCount;
    uint8_t * b = buffer_write_ptr(&data->clientBuffer, &readLimit);
    readCount = recv(key->fd, b, readLimit, 0);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }

    stats_add_client_bytes(readCount);  //@todo checkear todos los lugares donde poner esto
    buffer_write_adv(&data->clientBuffer, readCount);
    auth_parse result = authParse(p, &data->clientBuffer);
    switch (result) {
        case AUTH_PARSE_OK:
//            auth_parser *authParser = &data->client.authParser;
            if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || !sendAuthResponse(&data->originBuffer,p->version,0x00)) { //TODO validar usuario
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
    size_t readLimit;
    size_t readCount;
    uint8_t  * b = buffer_read_ptr(&data->originBuffer, &readLimit);
    readCount = send(key->fd, b, readLimit, MSG_NOSIGNAL);
    if (readCount <= 0) {
        return ERROR; // error o desconexión
    }
    stats_add_origin_bytes(readCount); //@Todo check donde va esto.
    buffer_read_adv(&data->originBuffer, readCount);

    if (buffer_can_read(&data->originBuffer)){
        return AUTHENTICATION_WRITE;
    }

   if (p->error || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    printf("Autenticación exitosa\n");
   printf("name: %s\n", p->name);
    printf("password: %s\n", p->password);
    return REQ_READ; // Continuar con la lectura de la solicitud
}