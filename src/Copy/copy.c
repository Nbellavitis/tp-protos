#include "copy.h"


void socksv5HandleInit(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("Iniciando copia de datos entre cliente y servidor (state es %d)\n", state);
    if(selector_set_interest(key->s, clientData->clientFd, OP_READ) != SELECTOR_SUCCESS) {
        printf("[ERROR] COPYING_INIT: Error configurando selector para lectura en el cliente\n");
        closeConnection(key);
        return;
    }
    if(selector_set_interest(key->s, clientData->originFd, OP_READ) != SELECTOR_SUCCESS) {
        printf("[ERROR] COPYING_INIT: Error configurando selector para lectura en el cliente\n");
        closeConnection(key);
        return;
    }
}

unsigned socksv5HandleRead(struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("[DEBUG] COPYING_READ: Leyendo datos del socket %d\n", key->fd);
    if (key->fd == clientData->clientFd) {
        // Datos del cliente -> servidor de origen
        printf("[DEBUG] COPYING_READ: Leyendo datos del cliente\n");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->originBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(key->fd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Cliente cerró conexión\n");
            return CLOSED;
        }

        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del cliente\n", bytes_read);
        buffer_write_adv(&clientData->originBuffer, bytes_read);

        // Cambiar a escritura en el socket de origen
        printf("[DEBUG] COPYING_READ: Configurando socket del servidor para escritura\n");
        if(selector_set_interest(key->s, clientData->originFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            printf("[ERROR] COPYING_READ: Error configurando selector para escritura en el origen\n");
            return ERROR;
        }
        return COPYING;

    } else if (key->fd == clientData->originFd) {
        // Datos del servidor de origen -> cliente
        printf("[DEBUG] COPYING_READ: Leyendo datos del servidor\n");
        size_t bytes_to_write;
        uint8_t *write_ptr = buffer_write_ptr(&clientData->clientBuffer, &bytes_to_write);
        ssize_t bytes_read = recv(clientData->originFd, write_ptr, bytes_to_write, 0);

        if (bytes_read <= 0) {
            printf("[DEBUG] COPYING_READ: Servidor cerró conexión\n");
            return CLOSED;
        }

        printf("[DEBUG] COPYING_READ: Leídos %zd bytes del servidor\n", bytes_read);
        buffer_write_adv(&clientData->clientBuffer, bytes_read);

        // Cambiar a escritura en el socket del cliente
        printf("[DEBUG] COPYING_READ: Configurando socket del cliente para escritura\n");
        if(selector_set_interest(key->s, clientData->clientFd, OP_WRITE)!= SELECTOR_SUCCESS) {
            printf("[ERROR] COPYING_READ: Error configurando selector para escritura en el cliente\n");
            return ERROR;
        }
        return COPYING;
    }

    printf("[ERROR] COPYING_READ: Socket desconocido: %d\n", key->fd);
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
            printf("[ERROR] socksv5HandleWrite: Error configurando selector para lectura en el cliente\n");
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
            printf("[ERROR] socksv5HandleWrite: Error configurando selector para lectura en el origen\n");
            return ERROR;
        }
        return COPYING;
    }

    return ERROR;
}

void socksv5HandleClose(const unsigned state, struct selector_key *key) {
    ClientData *clientData = (ClientData *)key->data;
    printf("Cerrando manejo de datos (state = %d, key = %p)\n", state, key);
}