#include "auth.h"
#include "../../logger.h"

bool validateUser(const char* username, const char* password) {
    if (username == NULL || password == NULL) {
        return false;
    }

    // todo: revisar lo hicimos con get porque no sabemos si estaría bien que desde acá pueda acceder al struct users users[MAX_USERS];
    struct users* users = get_authorized_users();
    int num_users = get_num_authorized_users();

    // Si no hay usuarios configurados, usamos usuario hardcodeado
    /* if (num_users == 0) {
         const char* valid_username = "admin";
         const char* valid_password = "password123";
         return (strcmp(username, valid_username) == 0 && strcmp(password, valid_password) == 0);
     }*/

    // Buscar en la lista de usuarios autorizados
    for (int i = 0; i < num_users; i++) {
        if (users[i].name != NULL && users[i].pass != NULL) {
            if (strcmp(username, users[i].name) == 0 && strcmp(password, users[i].pass) == 0) {
                return true;
            }
        }
    }

    return false;
}

void authenticationReadInit(unsigned state,struct selector_key * key){
    LOG_DEBUG("Authentication phase initialized (state: %d)", state);
    struct ClientData *data = (struct ClientData *)key->data;
    initAuthParser(&data->client.authParser);
}

unsigned authenticationRead(struct selector_key * key){
    ClientData *data = key->data;
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

    if (result == AUTH_PARSE_INCOMPLETE) {
        return AUTHENTICATION_READ;
    }
    if (result != AUTH_PARSE_OK) {
        return ERROR;
    }

    // Validar las credenciales del usuario
    if (!validateUser(p->name, p->password)) {
        LOG_WARN("Authentication failed for user: %s", p->name);
        if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || !sendAuthResponse(&data->originBuffer,p->version,0x01)) {
            return ERROR;
        }
        return ERROR; // Rechazar conexión por credenciales inválidas
    }

    LOG_INFO("Authentication successful for user: %s", p->name);
    // Guardar usuario para logging de acceso
    strncpy(data->username, p->name, sizeof(data->username) - 1);
    data->username[sizeof(data->username) - 1] = '\0'; // todo: chequear
    if(selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS || !sendAuthResponse(&data->originBuffer,p->version,0x00)) {
        return ERROR;
    }
    return authenticationWrite(key);

}

unsigned authenticationWrite(struct selector_key * key){
    ClientData *data = key->data;
    auth_parser *p = &data->client.authParser;
    size_t readLimit;
    const uint8_t  * b = buffer_read_ptr(&data->originBuffer, &readLimit);
    const size_t readCount = send(key->fd, b, readLimit, MSG_NOSIGNAL);

    if (readCount <= 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK)
               ? AUTHENTICATION_WRITE
               : ERROR;
    }



    stats_add_origin_bytes(readCount); //@Todo check donde va esto.
    buffer_read_adv(&data->originBuffer, readCount);

    if (buffer_can_read(&data->originBuffer)){
        return AUTHENTICATION_WRITE;
    }

    if (p->error || selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    LOG_DEBUG("Authenticated username: %s", p->name);
    return REQ_READ; // Continuar con la lectura de la solicitud
}