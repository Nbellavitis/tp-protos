#include "resolver_parser.h"
#include "../../logger.h"

void init_resolver_parser(resolver_parser *parser) {
    parser->version = 0;
    parser->command = 0;
    parser->reserved = 0;
    parser->address_type = 0;
    parser->port = 0;
    parser->state = RESOLVER_STATE_VERSION;
    parser->bytes_read = 0;
    parser->done = false;
    parser->error = false;
    memset(parser->ipv4_addr, 0, IPV4_ADDR_SIZE);
    memset(parser->ipv6_addr, 0, IPV6_ADDR_SIZE);
    memset(parser->domain, 0, MAX_DOMAIN_LEN);
    parser->domain_length = 0;
}


request_parse resolver_parse(resolver_parser *p, struct buffer *buffer) {
    uint8_t byte;

    while (buffer_can_read(buffer)) {
        byte = buffer_read(buffer);

        switch (p->state) {
            case RESOLVER_STATE_VERSION:
                if (byte != SOCKS5_VERSION) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->version = byte;
                p->state = RESOLVER_STATE_COMMAND;
                break;

            case RESOLVER_STATE_COMMAND:
                if (byte != CMD_CONNECT && byte != CMD_BIND && byte != CMD_UDP_ASSOCIATE) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->command = byte;
                p->state = RESOLVER_STATE_RESERVED;
                break;

            case RESOLVER_STATE_RESERVED:
                if (byte != 0x00) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->reserved = byte;
                p->state = RESOLVER_STATE_ATYP;
                break;

            case RESOLVER_STATE_ATYP:
                if (byte != ATYP_IPV4 && byte != ATYP_DOMAIN && byte != ATYP_IPV6) {
                    p->error = true;
                    return REQUEST_PARSE_ERROR;
                }
                p->address_type = byte;
                p->state = RESOLVER_STATE_ADDRESS;
                break;

            case RESOLVER_STATE_ADDRESS:
                switch (p->address_type) {
                    case ATYP_IPV4:
                        p->ipv4_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == IPV4_ADDR_SIZE) {
                            p->state = RESOLVER_STATE_PORT;
                            p->bytes_read = 0;
                        }
                        break;

                    case ATYP_DOMAIN:
                        if (p->bytes_read == 0) {
                            p->domain_length = byte;

                            if (p->domain_length == 0 ) {
                                p->error = true;
                                return REQUEST_PARSE_ERROR;
                            }
                            p->bytes_read = DOMAIN_LENGTH_OFFSET;
                        } else {
                            p->domain[p->bytes_read - DOMAIN_LENGTH_OFFSET] = byte;
                            p->bytes_read++;


                            if ((p->bytes_read - DOMAIN_LENGTH_OFFSET) == p->domain_length) {
                                p->state = RESOLVER_STATE_PORT;
                                p->bytes_read = 0;
                            }
                        }
                        break;

                    case ATYP_IPV6:
                        p->ipv6_addr[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == IPV6_ADDR_SIZE) {
                            p->state = RESOLVER_STATE_PORT;
                            p->bytes_read = 0;
                        }
                        break;
                }
                break;

            case RESOLVER_STATE_PORT:
                if (p->bytes_read == 0) {
                    p->port = ((uint16_t)byte) << PORT_HIGH_BYTE_SHIFT;
                    p->bytes_read = DOMAIN_LENGTH_OFFSET;
                } else {
                    p->port |= byte;
                    p->done = true;
                    return REQUEST_PARSE_OK;
                }
                break;
        }
    }

    return REQUEST_PARSE_INCOMPLETE;
}

bool prepare_request_response(struct buffer *origin_buffer, uint8_t version, uint8_t reply, uint8_t atyp, const void *bnd_addr, uint16_t bnd_port) {
    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    buffer_write(origin_buffer, version);

    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    buffer_write(origin_buffer, reply);

    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    buffer_write(origin_buffer, 0x00);

    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    buffer_write(origin_buffer, atyp);

    switch (atyp) {
        case ATYP_IPV4:

            if (!buffer_can_write(origin_buffer)) {
                return false;
            }
            for (int i = 0; i < IPV4_ADDR_SIZE; i++) {
                if (!buffer_can_write(origin_buffer)) {
                    return false;
                }
                buffer_write(origin_buffer, ((uint8_t*)bnd_addr)[i]);
            }
            break;
        case ATYP_IPV6:

            if (!buffer_can_write(origin_buffer)) {
                return false;
            }
            for (int i = 0; i < IPV6_ADDR_SIZE; i++) {
                if (!buffer_can_write(origin_buffer)) {
                    return false;
                }
                buffer_write(origin_buffer, ((uint8_t*)bnd_addr)[i]);
            }
            break;
        case ATYP_DOMAIN: {
            uint8_t domain_len = strlen((char*)bnd_addr);

            if (!buffer_can_write(origin_buffer)) {
                return false;
            }
            buffer_write(origin_buffer, domain_len);

            for (int i = 0; i < domain_len; i++) {
                if (!buffer_can_write(origin_buffer)) {
                    return false;
                }
                buffer_write(origin_buffer, ((char*)bnd_addr)[i]);
            }
            break;
        }
    }

    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    uint16_t port_network = htons(bnd_port);
    buffer_write(origin_buffer, (port_network >> PORT_HIGH_BYTE_SHIFT) & BYTE_MASK);

    if (!buffer_can_write(origin_buffer)) {
        return false;
    }

    buffer_write(origin_buffer, port_network & BYTE_MASK);

    return true;
}
