#include "copy.h"
#include "../../logger.h"

static bool update_interests(const struct selector_key *key) {
    ClientData *d = (ClientData *)key->data;
    fd_interest client_interest = OP_NOOP;
    fd_interest origin_interest = OP_NOOP;

    // Calcular interés para el socket del cliente (clientFd)
    if (buffer_can_write(&d->originBuffer)) {
        client_interest |= OP_READ;
    }
    if (buffer_can_read(&d->clientBuffer)) {
        client_interest |= OP_WRITE;
    }

    // Calcular interés para el socket de destino (originFd)
    if (buffer_can_write(&d->clientBuffer)) {
        origin_interest |= OP_READ;
    }
    if (buffer_can_read(&d->originBuffer)) {
        origin_interest |= OP_WRITE;
    }

    if (selector_set_interest(key->s, d->clientFd, client_interest) != SELECTOR_SUCCESS || selector_set_interest(key->s, d->originFd, origin_interest) != SELECTOR_SUCCESS) {
        return false;
    }

    return true;
}


void socksv5HandleInit(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("COPYING_INIT: Starting data copy between client and origin (state = %d)", state);
    if (!update_interests(key)) {
        closeConnection(key);
    }
}

unsigned socksv5HandleRead(struct selector_key *key) {
    ClientData *d = (ClientData *)key->data;
    buffer *target_buffer;
    int source_fd, dest_fd;

    if (key->fd == d->clientFd) {
        source_fd = d->clientFd;
        dest_fd = d->originFd;
        target_buffer = &d->originBuffer;
    } else {
        source_fd = d->originFd;
        dest_fd = d->clientFd;
        target_buffer = &d->clientBuffer;
    }

    // Leemos del socket
    size_t capacity;
    uint8_t *ptr = buffer_write_ptr(target_buffer, &capacity);
    ssize_t n = recv(source_fd, ptr, capacity, 0);
    if (n <= 0) {
        return CLOSED;
    }
    buffer_write_adv(target_buffer, n);

    if (source_fd == d->clientFd) {
        stats_add_client_bytes(n);
    } else {
        stats_add_origin_bytes(n);
    }


    // Intentamos escribir en el otro socket
    if (!buffer_flush(target_buffer, dest_fd, NULL)) {
        return ERROR;
    }

    // Actualizamos los intereses y retornamos
    return update_interests(key) ? COPYING : ERROR;
}

unsigned socksv5HandleWrite(const struct selector_key *key) {
    ClientData *d = (ClientData *)key->data;

    if (key->fd == d->clientFd) {
        if (!buffer_flush( &d->clientBuffer, d->clientFd, NULL)) {
            return ERROR;
        }
    } else {
        if (!buffer_flush(&d->originBuffer, d->originFd, NULL)) {
            return ERROR;
        }
    }

    return update_interests(key) ? COPYING : ERROR;
}


void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("%s" , "COPYING_CLOSE: Closing data handling");
}

