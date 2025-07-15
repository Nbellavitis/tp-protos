#include "negotiation.h"
#include "negotiation_parser.h"
#include <errno.h>
#include "../../logger.h"
#define VERSION_5 0x05
void negotiation_read_init(unsigned state, struct selector_key *key) {
    struct client_data *data = (struct client_data *)key->data;
    init_negotiation_parser(&data->client.neg_parser);
}



unsigned negotiation_read(struct selector_key *key) {
    client_data *data = key->data;
    negotiation_parser *p = &data->client.neg_parser;
    size_t read_limit;
    uint8_t *b = buffer_write_ptr(&data->client_buffer, &read_limit);
    const ssize_t read_count = recv(key->fd, b, read_limit, 0);
    if (read_count <= 0) {
        return ERROR;
    }
    stats_add_client_bytes(read_count);

    buffer_write_adv(&data->client_buffer, read_count);
    negotiation_parse_result result = negotiation_parse(p, &data->client_buffer);

    if (result == NEGOTIATION_PARSE_INCOMPLETE) {
        return NEGOTIATION_READ;
    }


    if (result != NEGOTIATION_PARSE_OK) {
        data->auth_failed = true;
        p->method_chosen = NO_ACCEPTABLE_METHODS;
        return ERROR;
    }

    if(p->method_chosen == NO_ACCEPTABLE_METHODS){
        data->auth_failed = true;
    }


    if (!send_negotiation_response(&data->origin_buffer, p->method_chosen)) {
        return ERROR;
    }

    return negotiation_write(key);
}

void negotiation_write_init(const unsigned state, struct selector_key *key) {
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        close_connection(key);
    }
}

unsigned negotiation_write(struct selector_key *key) {
    client_data *data = key->data;

    ssize_t bytes_written;
    if (!buffer_flush(&data->origin_buffer, key->fd, &bytes_written)) {
        return ERROR;
    }

    stats_add_origin_bytes(bytes_written);

    if (buffer_can_read(&data->origin_buffer)) {
        return NEGOTIATION_WRITE;
    }

    negotiation_parser *p = &data->client.neg_parser;
    if (p->method_chosen == NO_ACCEPTABLE_METHODS) {
        return ERROR;
    }

    if (p->method_chosen == NOAUTH ) {
        return REQ_READ;
    }

    return AUTHENTICATION_READ;

}