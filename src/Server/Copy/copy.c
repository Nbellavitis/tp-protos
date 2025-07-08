#include "copy.h"
#include "../../logger.h"


void socksv5HandleInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_INIT: Starting data copy between client and origin (state = %d)", state);

    // Determinar el interés inicial para el FILE DESCRIPTOR DEL CLIENTE.
    // Si ya tenemos datos del origen --> OP_WRITE
    // Si no --> OP_READ
    fd_interest client_interest = buffer_can_read(&clientData->clientBuffer) ? OP_WRITE : OP_READ;

    // Determinar el interés inicial para el FILE DESCRIPTOR DE DESTINO (ORIGIN).
    // Si ya tenemos datos del cliente para enviarle al destino (el caso que te preocupa),
    // entonces nos interesa escribir en el destino. Si no, nos interesa leer de él.
    fd_interest origin_interest = buffer_can_read(&clientData->originBuffer) ? OP_WRITE : OP_READ;

    // Registrar los intereses correctos en el selector.
    if (selector_set_interest(key->s, clientData->clientFd, client_interest) != SELECTOR_SUCCESS) {
        LOG_ERROR("COPYING_INIT: Error setting initial interest for client");
        closeConnection(key);
        return;
    }
    if (selector_set_interest(key->s, clientData->originFd, origin_interest) != SELECTOR_SUCCESS) {
        LOG_ERROR("COPYING_INIT: Error setting initial interest for origin");
        closeConnection(key);
        return;
    }
}

unsigned socksv5HandleRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_READ: Reading data from socket %d", key->fd);
    if (key->fd == clientData->clientFd) {
        // Datos del cliente -> servidor de origen
        LOG_DEBUG("COPYING_READ: Reading data from client");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(key->fd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            LOG_DEBUG("COPYING_READ: Client closed connection");
            return CLOSED;
        }

        LOG_DEBUG("COPYING_READ: Read %zd bytes from client", bytes_read);
        buffer_write_adv(&clientData->originBuffer, bytes_read);

        // Cambiar a escritura en el socket de origen
        LOG_DEBUG("COPYING_READ: Setting server socket for writing");
        if(selector_set_interest(key->s, clientData->originFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            LOG_ERROR("COPYING_READ: Error setting selector for write on origin");
            return ERROR;
        }
        return COPYING;

    } else if (key->fd == clientData->originFd) {
        // Datos del servidor de origen -> cliente
        LOG_DEBUG("COPYING_READ: Reading data from server");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->clientBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(clientData->originFd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            LOG_DEBUG("COPYING_READ: Server closed connection");
            return CLOSED;
        }

        LOG_DEBUG("COPYING_READ: Read %zd bytes from server", bytes_read);
        buffer_write_adv(&clientData->clientBuffer, bytes_read);

        // Cambiar a escritura en el socket del cliente
        LOG_DEBUG("COPYING_READ: Setting client socket for writing");
        if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            LOG_ERROR("COPYING_READ: Error setting selector for write on client");
            return ERROR;
        }
        return COPYING;
    }

    LOG_ERROR("COPYING_READ: Unknown socket: %d", key->fd);
    return ERROR;
}

unsigned socksv5HandleWrite(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;

    // Escribir datos del buffer al socket correspondiente
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

            if (buffer_can_read(&clientData->clientBuffer)) {
                return COPYING;
            }
        }

        // Cambiar a lectura en el socket del cliente
        if(selector_set_interest(key->s, clientData->clientFd, OP_READ)){
            LOG_ERROR("socksv5HandleWrite: Error setting selector for read on client");
            return ERROR;
        }
        return COPYING;

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

            if (buffer_can_read(&clientData->originBuffer)) {
                return COPYING;
            }
        }

        // Cambiar a lectura en el socket del servidor de origen
        if(selector_set_interest(key->s, clientData->originFd, OP_READ) != SELECTOR_SUCCESS) {
            LOG_ERROR("socksv5HandleWrite: Error setting selector for read on origin");
            return ERROR;
        }
        return COPYING;
    }

    return ERROR;
}

void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    LOG_DEBUG("COPYING_CLOSE: Closing data handling (state = %d, key = %p)", state, key);
}