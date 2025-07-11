/**
 * buffer.c - buffer con acceso directo (útil para I/O) que mantiene
 *            mantiene puntero de lectura y de escritura.
 */
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "buffer.h"

inline void
buffer_reset(buffer *b) {
    b->read  = b->data;
    b->write = b->data;
}

void
buffer_init(buffer *b, const size_t n, uint8_t *data) {
    b->data = data;
    buffer_reset(b);
    b->limit = b->data + n;
}


inline bool
buffer_can_write(buffer *b) {
    return b->limit - b->write > 0;
}

inline uint8_t *
buffer_write_ptr(buffer *b, size_t *nbyte) {
    assert(b->write <= b->limit);
    *nbyte = b->limit - b->write;
    return b->write;
}

inline bool
buffer_can_read(buffer *b) {
    return b->write - b->read > 0;
}

inline uint8_t *
buffer_read_ptr(buffer *b, size_t *nbyte) {
    assert(b->read <= b->write);
    *nbyte = b->write - b->read;
    return b->read;
}

inline void
buffer_write_adv(buffer *b, const ssize_t bytes) {
    if(bytes > -1) {
        b->write += (size_t) bytes;
        assert(b->write <= b->limit);
    }
}

inline void
buffer_read_adv(buffer *b, const ssize_t bytes) {
    if(bytes > -1) {
        b->read += (size_t) bytes;
        assert(b->read <= b->write);

        if(b->read == b->write) {
            // compactacion poco costosa
            buffer_compact(b);
        }
    }
}

inline uint8_t
buffer_read(buffer *b) {
    uint8_t ret;
    if(buffer_can_read(b)) {
        ret = *b->read;
        buffer_read_adv(b, 1);
    } else {
        ret = 0;
    }
    return ret;
}

inline void
buffer_write(buffer *b, uint8_t c) {
    if(buffer_can_write(b)) {
        *b->write = c;
        buffer_write_adv(b, 1);
    }
}

void
buffer_compact(buffer *b) {
    if(b->data == b->read) {
        // nada por hacer
    } else if(b->read == b->write) {
        b->read  = b->data;
        b->write = b->data;
    } else {
        const size_t n = b->write - b->read;
        memmove(b->data, b->read, n);
        b->read  = b->data;
        b->write = b->data + n;
    }
}


bool
buffer_flush(buffer *b, const int fd, ssize_t *bytes_sent) {
    // Inicializamos el valor de salida opcional.
    if (bytes_sent != NULL) {
        *bytes_sent = 0;
    }

    if (!buffer_can_read(b)) {
        // No hay nada para leer del buffer, no falla.
        return true;
    }

    size_t write_len;
    uint8_t *ptr = buffer_read_ptr(b, &write_len);
    ssize_t sent = send(fd, ptr, write_len, MSG_NOSIGNAL);

    // Guardamos el resultado de send() en el parámetro de salida si no es nulo.
    if (bytes_sent != NULL) {
        *bytes_sent = sent;
    }

    if (sent > 0) {
        // Éxito: se enviaron algunos bytes.
        buffer_read_adv(b, sent);
        return true;
    }

    if (sent == 0) {
        // El otro extremo cerró la conexión. Es una condición de cierre.
        return false;
    }

    // sent < 0
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // El buffer asociado al socket está lleno. No es un error fatal, se puede reintentar.
        return true;
    }

    // Es un error de escritura irrecuperable.
    return false;
}