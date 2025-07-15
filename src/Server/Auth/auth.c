#include "auth.h"
#include "../../logger.h"

user_t *validate_user(const char *username, const char *password) {
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

void authentication_read_init(const unsigned state,  struct selector_key *key){
    struct client_data *data = (struct client_data *)key->data;
    init_auth_parser(&data->client.auth_parser);
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        close_connection(key);
    }
}


static unsigned process_auth_flush(const struct selector_key *key, const unsigned on_block_state, const unsigned on_complete_state) {
    client_data *data = (client_data *)key->data;

    ssize_t bytes_written;
    if (!buffer_flush(&data->origin_buffer, key->fd, &bytes_written)) {
        return ERROR;
    }

    stats_add_origin_bytes(bytes_written);

    if (buffer_can_read(&data->origin_buffer)) {
        return on_block_state;
    }

    return on_complete_state;
}




unsigned authentication_read(struct selector_key *key) {
    client_data *data = key->data;
    auth_parser *p = &data->client.auth_parser;
    size_t read_limit;
    uint8_t *b = buffer_write_ptr(&data->client_buffer, &read_limit);
    const ssize_t read_count = recv(key->fd, b, read_limit, 0);
    if (read_count <= 0) {
        return ERROR;
    }

    stats_add_client_bytes(read_count);
    buffer_write_adv(&data->client_buffer, read_count);
    const auth_parse_result result = auth_parse(p, &data->client_buffer);

    if (result == AUTH_PARSE_INCOMPLETE) {
        return AUTHENTICATION_READ;
    }
    if (result != AUTH_PARSE_OK) {
        return ERROR;
    }

    user_t * user = validate_user(p->name, p->password);
    bool is_valid = false;
    uint8_t status;
    if (user != NULL ) {
       data->user = user;
       is_valid = true;
       status = AUTH_STATUS_SUCCESS;
    } else {
        LOG_WARN("Authentication failed for user: %s", p->name);
        status = data->socks_status= AUTH_STATUS_FAILURE;
        data->auth_failed = true;
    }

    if (!send_auth_response(&data->origin_buffer, p->version, status)) {
        return ERROR;
    }

    return is_valid ? authentication_write(key) : authentication_failure_write(key);
}

void authentication_write_init(const unsigned state, struct selector_key *key) {
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        close_connection(key);
    }
}

unsigned authentication_write(struct selector_key *key) {
    return process_auth_flush(key, AUTHENTICATION_WRITE, REQ_READ);
}

unsigned authentication_failure_write(struct selector_key *key) {
    return process_auth_flush(key, AUTHENTICATION_FAILURE_WRITE, ERROR);
}
