#include "copy.h"
#include "../../logger.h"


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
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_INIT: Starting data copy between client and origin (state = %d)", state);
    if (!copy_update_interests(key)) {
        closeConnection(key);
    }
}

// void socksv5HandleInit(const unsigned state, struct selector_key *key) {
//     ClientData *clientData = (ClientData *)key->data;
//     LOG_DEBUG("COPYING_INIT: Starting data copy between client and origin (state = %d)", state);
//
//     fd_interest client_interest = buffer_can_read(&clientData->clientBuffer) ? OP_WRITE : OP_READ;
//
//     fd_interest origin_interest = buffer_can_read(&clientData->originBuffer) ? OP_WRITE : OP_READ;
//
//     // Registrar los intereses correctos en el selector.
//     if (selector_set_interest(key->s, clientData->clientFd, client_interest) != SELECTOR_SUCCESS) {
//         LOG_ERROR("COPYING_INIT: Error setting initial interest for client");
//         closeConnection(key);
//         return;
//     }
//     if (selector_set_interest(key->s, clientData->originFd, origin_interest) != SELECTOR_SUCCESS) {
//         LOG_ERROR("COPYING_INIT: Error setting initial interest for origin");
//         closeConnection(key);
//         return;
//     }
// }

unsigned socksv5HandleRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_READ: Reading data from socket %d", key->fd);

    if (key->fd == clientData->clientFd) {
        // Datos del cliente -> servidor de origen
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(key->fd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            LOG_DEBUG("COPYING_READ: Client closed connection");
            return CLOSED;
        }

        buffer_write_adv(&clientData->originBuffer, bytes_read);
    } else if (key->fd == clientData->originFd) {
        // Datos del servidor de origen -> cliente
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->clientBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(clientData->originFd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            LOG_DEBUG("COPYING_READ: Server closed connection");
            return CLOSED;
        }

        buffer_write_adv(&clientData->clientBuffer, bytes_read);
    }

    if (!copy_update_interests(key)) {
        LOG_ERROR("COPYING_READ: Error setting selector");
        return ERROR;
    }
    return COPYING;
}

unsigned socksv5HandleWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    if (key->fd == clientData->clientFd) {
        // Escribir datos del buffer del cliente al cliente
        if (buffer_can_read(&clientData->clientBuffer)) {
            size_t bytes_to_write;
            uint8_t *read_ptr = buffer_read_ptr(&clientData->clientBuffer, &bytes_to_write);
            ssize_t bytes_written = send(clientData->clientFd, read_ptr, bytes_to_write, MSG_NOSIGNAL);

            if (bytes_written < 0) {
                return ERROR;
            }
            buffer_read_adv(&clientData->clientBuffer, bytes_written);
        }
    } else if (key->fd == clientData->originFd) {
        // Escribir datos del buffer del origen al servidor de origen
        if (buffer_can_read(&clientData->originBuffer)) {
            size_t bytes_to_write;
            uint8_t *read_ptr = buffer_read_ptr(&clientData->originBuffer, &bytes_to_write);
            ssize_t bytes_written = send(clientData->originFd, read_ptr, bytes_to_write, MSG_NOSIGNAL);

            if (bytes_written < 0) {
                return ERROR;
            }
            buffer_read_adv(&clientData->originBuffer, bytes_written);
        }
    }

    copy_update_interests(key);
    return COPYING;
}

void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_CLOSE: Closing data handling (state = %d, key = %p)", state, key);
}

