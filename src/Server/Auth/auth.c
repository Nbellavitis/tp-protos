#include "auth.h"
#include "../../logger.h"

user_t *validateUser(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        return NULL;
    }
    user_t *users = get_authorized_users();
    int num_users = get_num_authorized_users();

    for (int i = 0; i < num_users; i++) {
        if (users[i].name && users[i].pass &&
            strcmp(username, users[i].name) == 0 &&
            strcmp(password, users[i].pass) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

void authenticationReadInit(const unsigned state,  struct selector_key *key){
    LOG_DEBUG("Authentication phase initialized (state: %d)", state);
    struct ClientData *data = (struct ClientData *)key->data;
    initAuthParser(&data->client.authParser);
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        closeConnection(key);
    }
}


static unsigned process_auth_flush(const struct selector_key *key, const unsigned on_block_state, const unsigned on_complete_state) {
    ClientData *data = (ClientData *)key->data;

    ssize_t bytes_written;
    if (!buffer_flush(&data->originBuffer, key->fd, &bytes_written)) {
        return ERROR;
    }

    stats_add_origin_bytes(bytes_written);

    // Si la escritura se bloqueó, volvemos al estado de escritura correspondiente.
    if (buffer_can_read(&data->originBuffer)) {
        return on_block_state;
    }

    return on_complete_state;
}




unsigned authenticationRead(struct selector_key *key) {
    ClientData *data = key->data;
    auth_parser *p = &data->client.authParser;
    size_t readLimit;
    uint8_t *b = buffer_write_ptr(&data->clientBuffer, &readLimit);
    const ssize_t readCount = recv(key->fd, b, readLimit, 0);
    if (readCount <= 0) {
        return ERROR;
    }

    stats_add_client_bytes(readCount);
    buffer_write_adv(&data->clientBuffer, readCount);
    const auth_parse result = authParse(p, &data->clientBuffer);

    if (result == AUTH_PARSE_INCOMPLETE) {
        return AUTHENTICATION_READ;
    }
    if (result != AUTH_PARSE_OK) {
        return ERROR;
    }

    user_t * user = validateUser(p->name, p->password);
    bool is_valid = false;
    uint8_t status;
    if (user != NULL ) {
//        LOG_INFO("Authentication successful for user: %s", p->name);
       /* strncpy(data->username, p->name, sizeof(data->username) - 1);
        data->username[sizeof(data->username) - 1] = '\0';*/
       data->user = user;
       is_valid = true;
       status = AUTH_STATUS_SUCCESS;
    } else {
        LOG_WARN("Authentication failed for user: %s", p->name);
        status = data->socks_status= AUTH_STATUS_FAILURE;
        data->authFailed = true;
    }

    // Preparar la respuesta y registrar el interés para escribir
    if (!sendAuthResponse(&data->originBuffer, p->version, status)) {
        return ERROR;
    }

    return is_valid ? authenticationWrite(key) : authenticationFailureWrite(key);
}

void authenticationWriteInit(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("AUTHENTICATION_WRITE_INIT: Setting interest to OP_WRITE");
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        closeConnection(key);
    }
}

unsigned authenticationWrite(struct selector_key *key) {
    return process_auth_flush(key, AUTHENTICATION_WRITE, REQ_READ);
}

// Nueva función que SOLO maneja el caso de FALLO.
unsigned authenticationFailureWrite(struct selector_key *key) {
    return process_auth_flush(key, AUTHENTICATION_FAILURE_WRITE, ERROR);
}
