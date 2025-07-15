#include "copy.h"
#include "../../logger.h"

static bool update_interests(const struct selector_key *key) {
    client_data *d = (client_data *)key->data;
    fd_interest client_interest = OP_NOOP;
    fd_interest origin_interest = OP_NOOP;

    if (buffer_can_write(&d->origin_buffer)) {
        client_interest |= OP_READ;
    }
    if (buffer_can_read(&d->client_buffer)) {
        client_interest |= OP_WRITE;
    }

    if (buffer_can_write(&d->client_buffer)) {
        origin_interest |= OP_READ;
    }
    if (buffer_can_read(&d->origin_buffer)) {
        origin_interest |= OP_WRITE;
    }

    if (selector_set_interest(key->s, d->client_fd, client_interest) != SELECTOR_SUCCESS || selector_set_interest(key->s, d->origin_fd, origin_interest) != SELECTOR_SUCCESS) {
        return false;
    }

    return true;
}


void socksv5_handle_init(const unsigned state, struct selector_key *key) {
    if (!update_interests(key)) {
        close_connection(key);
    }
}

unsigned socksv5_handle_read(struct selector_key *key) {
    client_data *d = (client_data *)key->data;
    buffer *target_buffer;
    int source_fd, dest_fd;

    if (key->fd == d->client_fd) {
        source_fd = d->client_fd;
        dest_fd = d->origin_fd;
        target_buffer = &d->origin_buffer;
    } else {
        source_fd = d->origin_fd;
        dest_fd = d->client_fd;
        target_buffer = &d->client_buffer;
    }

    size_t capacity;
    uint8_t *ptr = buffer_write_ptr(target_buffer, &capacity);
    ssize_t n = recv(source_fd, ptr, capacity, 0);
    if (n <= 0) {
        return CLOSED;
    }
    buffer_write_adv(target_buffer, n);

    if (source_fd == d->client_fd) {
        stats_add_client_bytes(n);
    } else {
        stats_add_origin_bytes(n);
    }


    if (!buffer_flush(target_buffer, dest_fd, NULL)) {
        return ERROR;
    }

    return update_interests(key) ? COPYING : ERROR;
}

unsigned socksv5_handle_write( struct selector_key *key) {
    client_data *d = (client_data *)key->data;

    if (key->fd == d->client_fd) {
        if (!buffer_flush( &d->client_buffer, d->client_fd, NULL)) {
            return ERROR;
        }
    } else {
        if (!buffer_flush(&d->origin_buffer, d->origin_fd, NULL)) {
            return ERROR;
        }
    }

    return update_interests(key) ? COPYING : ERROR;
}



