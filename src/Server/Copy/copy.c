#include "copy.h"
#include "../../logger.h"

// flushea el buffer b en el fd, si hay error retorna false
static bool flush_buffer(int fd, buffer *b) {
    if (!buffer_can_read(b)) {
        // No hay nada para escribir, no es un error.
        return true;
    }

    size_t write_len;
    uint8_t *ptr = buffer_read_ptr(b, &write_len);
    ssize_t bytes_sent = send(fd, ptr, write_len, MSG_NOSIGNAL);

    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // El buffer asociado al fd está lleno, no es un error
            return true;
        }

        LOG_ERROR("flush_buffer: Error writing to socket: %s", strerror(errno));
        return false;
    }

    if (bytes_sent == 0 && write_len > 0) {
        LOG_ERROR("%s" ,"flush_buffer: send() returned 0, peer closed connection.");
        return false;
    }

    buffer_read_adv(b, bytes_sent);
    return true;
}


static bool copy_update_interests(struct selector_key *key) {
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
    if (!copy_update_interests(key)) {
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
    if (!flush_buffer(dest_fd, target_buffer)) {
        return ERROR;
    }

    // Actualizamos los intereses y retornamos
    return copy_update_interests(key) ? COPYING : ERROR;
}

unsigned socksv5HandleWrite(struct selector_key *key) {
    ClientData *d = (ClientData *)key->data;

    if (key->fd == d->clientFd) {
        if (!flush_buffer(d->clientFd, &d->clientBuffer)) {
            return ERROR;
        }
    } else {
        if (!flush_buffer(d->originFd, &d->originBuffer)) {
            return ERROR;
        }
    }

    return copy_update_interests(key) ? COPYING : ERROR;
}

// TODO: creo que no tiene sentido esto:
void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    LOG_DEBUG("COPYING_CLOSE: Closing data handling (state = %d, key = %p)", state, key);
}

