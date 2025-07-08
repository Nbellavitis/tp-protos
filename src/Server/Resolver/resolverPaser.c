#include "resolverParser.h"
#include "../../logger.h"

void initResolverParser(resolver_parser *parser) {
    parser->version = 0;
    parser->command = 0;
    parser->reserved = 0;
    parser->address_type = 0;
    parser->port = 0;
    parser->state = 0;
    parser->bytes_read = 0;
    parser->done = false;
    parser->error = false;
    memset(parser->ipv4_addr, 0, 4);
    memset(parser->ipv6_addr, 0, 16);
    memset(parser->domain, 0, 256);
    parser->domain_length = 0;
}


request_parse resolverParse(resolver_parser *p, struct buffer *buffer) {
    uint8_t byte;

    while (buffer_can_read(buffer)) {
        byte = buffer_read(buffer);

        switch (p->state) {
            case 0: // en este estado vamos a leer VER
                if (byte != 0x05) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->version = byte;
                p->state = 1;
                break;

            case 1: // leemos CMD
                if (byte != CMD_CONNECT && byte != CMD_BIND && byte != CMD_UDP_ASSOCIATE) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->command = byte;
                p->state = 2;
                break;

            case 2: // leemos RSV
                if (byte != 0x00) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->reserved = byte;
                p->state = 3;
                break;

            case 3: // leemos ATYP
                if (byte != ATYP_IPV4 && byte != ATYP_DOMAIN && byte != ATYP_IPV6) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->address_type = byte;
                p->state = 4;
                break;

            case 4: // leemos DST.ADDR
                switch (p->address_type) {
                    case ATYP_IPV4:
                        p->ipv4_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == 4) {
                            p->state = 5;
                            p->bytes_read = 0;
                        }
                        break;

                    case ATYP_DOMAIN:
                        if (p->bytes_read == 0) {
                            p->domain_length = byte;
                            // Validar que domain_length no exceda el buffer
                            if (p->domain_length == 0 || p->domain_length > 255) {
                                p->error = true;
                                return REQUEST_PARSE_ERROR;
                            }
                            p->bytes_read = 1;  // Lee un byte que va a ser la longitud del dominio
                        } else {
                            // Verificar bounds antes de escribir
                            if (p->bytes_read - 1 >= 255) {
                                p->error = true;
                                return REQUEST_PARSE_ERROR;
                            }
                            p->domain[p->bytes_read - 1] = byte;
                            p->bytes_read++;
                            if (p->bytes_read > p->domain_length) {
                                p->state = 5;
                                p->bytes_read = 0;
                            }
                        }
                        break;

                    case ATYP_IPV6:
                        p->ipv6_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == 16) {
                            p->state = 5;
                            p->bytes_read = 0;
                        }
                        break;
                }
                break;

            case 5: // DST.PORT
                if (p->bytes_read == 0) {
                    LOG_DEBUG("Byte received: 0x%02x in state", byte);
                    p->port = ((uint16_t)byte) << 8; // high byte
                    p->bytes_read = 1;
                } else {
                    p->port |= byte; // low byte
                    // Convertir a host order (ya está en host order por el armado manual)
                    LOG_DEBUG("Byte received: 0x%02x in state", byte);
                    p->done = true;
                    return REQUEST_PARSE_OK;
                }
                break;
        }
    }

    return REQUEST_PARSE_INCOMPLETE;
}

bool prepareRequestResponse(struct buffer *originBuffer, uint8_t version, uint8_t reply, uint8_t atyp, const void *bnd_addr, uint16_t bnd_port) {
    // Verificar espacio disponible antes de escribir
    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full, cannot write");
        return false;
    }

    // VER
    buffer_write(originBuffer, version);

    // Verificar espacio para REP
    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full after VER");
        return false;
    }

    // REP
    buffer_write(originBuffer, reply);

    // Verificar espacio para RSV
    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full after REP");
        return false;
    }

    // RSV
    buffer_write(originBuffer, 0x00);

    // Verificar espacio para ATYP
    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full after RSV");
        return false;
    }

    // ATYP
    buffer_write(originBuffer, atyp);

    // BND.ADDR
    switch (atyp) {
        case ATYP_IPV4:
            // Verificar espacio para 4 bytes de IPv4
            if (!buffer_can_write(originBuffer)) {
                LOG_DEBUG("sendRequestResponse: Buffer full for IPv4");
                return false;
            }
            for (int i = 0; i < 4; i++) {
                if (!buffer_can_write(originBuffer)) {
                    LOG_DEBUG("sendRequestResponse: Buffer full during IPv4");
                    return false;
                }
                buffer_write(originBuffer, ((uint8_t*)bnd_addr)[i]);
            }
            break;
        case ATYP_IPV6:
            // Verificar espacio para 16 bytes de IPv6
            if (!buffer_can_write(originBuffer)) {
                LOG_DEBUG("sendRequestResponse: Buffer full for IPv6");
                return false;
            }
            for (int i = 0; i < 16; i++) {
                if (!buffer_can_write(originBuffer)) {
                    LOG_DEBUG("sendRequestResponse: Buffer full during IPv6");
                    return false;
                }
                buffer_write(originBuffer, ((uint8_t*)bnd_addr)[i]);
            }
            break;
        case ATYP_DOMAIN: {
            uint8_t domain_len = strlen((char*)bnd_addr);
            // Verificar espacio para longitud
            if (!buffer_can_write(originBuffer)) {
                LOG_DEBUG("sendRequestResponse: Buffer full for domain length");
                return false;
            }
            buffer_write(originBuffer, domain_len);

            // Verificar espacio para dominio
            for (int i = 0; i < domain_len; i++) {
                if (!buffer_can_write(originBuffer)) {
                    LOG_DEBUG("sendRequestResponse: Buffer full during domain");
                    return false;
                }
                buffer_write(originBuffer, ((char*)bnd_addr)[i]);
            }
            break;
        }
    }

    // Verificar espacio para puerto (2 bytes)
    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full for port");
        return false;
    }

    // BND.PORT (network byte order)
    uint16_t port_network = htons(bnd_port);
    buffer_write(originBuffer, (port_network >> 8) & 0xFF);

    if (!buffer_can_write(originBuffer)) {
        LOG_DEBUG("sendRequestResponse: Buffer full for second port byte");
        return false;
    }

    buffer_write(originBuffer, port_network & 0xFF);

    LOG_DEBUG("sendRequestResponse: SOCKS5 response sent to buffer");
    return true;
}
