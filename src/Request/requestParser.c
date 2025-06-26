#include "requestParser.h"
#include <string.h>
#include <arpa/inet.h>

#define SOCKS_VERSION_5 0x05

void initRequestParser(request_parser *p) {
    memset(p, 0, sizeof(*p));
}

request_parse requestParse(request_parser *p, struct buffer *b) {
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);

        if (p->version == 0) {
            p->version = byte;
            if (p->version != SOCKS_VERSION_5) {
                p->error = true;
                return REQUEST_PARSE_ERROR;
            }
            continue;
        }

        if (p->cmd == 0) {
            p->cmd = byte;
            if (p->cmd < 0x01 || p->cmd > 0x03) {
                p->error = true;
                return REQUEST_PARSE_ERROR;
            }
            continue;
        }

        if (!p->rsv_read) {
            p->rsv = byte;
            if (p->rsv != 0x00) {
                p->error = true;
                return REQUEST_PARSE_ERROR;
            }
            p->rsv_read = true;
            continue;
        }

        if (p->atyp == 0) {
            p->atyp = byte;
            if (p->atyp != 0x01 && p->atyp != 0x03 && p->atyp != 0x04) {
                p->error = true;
                return REQUEST_PARSE_ERROR;
            }
            continue;
        }

        if (!p->reading_port) {
            switch (p->atyp) {
                case 0x01:
                    p->dest_addr[p->bytes_read++] = byte;
                    if (p->bytes_read == 4) {
                        inet_ntop(AF_INET, p->dest_addr, p->dest_addr_str, sizeof p->dest_addr_str);
                        p->reading_port = true;
                        p->bytes_read = 0;
                    }
                    break;

                case 0x04:
                    p->dest_addr[p->bytes_read++] = byte;
                    if (p->bytes_read == 16) {
                        inet_ntop(AF_INET6, p->dest_addr, p->dest_addr_str, sizeof p->dest_addr_str);
                        p->reading_port = true;
                        p->bytes_read = 0;
                    }
                    break;

                case 0x03:
                    if (p->addr_len == 0) {
                        p->addr_len = byte;
                        if (p->addr_len == 0) {
                            p->error = true;
                            return REQUEST_PARSE_ERROR;
                        }
                    } else {
                        p->dest_addr[p->bytes_read]     = byte;
                        p->dest_addr_str[p->bytes_read] = byte;
                        p->bytes_read++;
                        if (p->bytes_read == p->addr_len) {
                            p->dest_addr_str[p->bytes_read] = '\0';
                            p->reading_port = true;
                            p->bytes_read = 0;
                        }
                    }
                    break;
            }
            continue;
        }

        if (!p->port_hi_read) {
            p->dest_port = byte << 8;
            p->port_hi_read = true;
        } else {
            p->dest_port |= byte;
            return REQUEST_PARSE_OK;
        }
    }
    return REQUEST_PARSE_INCOMPLETE;
}

bool sendRequestResponse(struct buffer *out, uint8_t version, uint8_t reply) {
    if (buffer_can_write(out) < 10)
        return false;

    buffer_write(out, version);
    buffer_write(out, reply);
    buffer_write(out, 0x00);
    buffer_write(out, 0x01);
    for (int i = 0; i < 4; i++)
        buffer_write(out, 0x00);
    buffer_write(out, 0x00);
    buffer_write(out, 0x00);

    return true;
}
