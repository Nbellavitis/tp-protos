#ifndef PROTOCOL_CONSTANTS_H
#define PROTOCOL_CONSTANTS_H

#define SOCKS5_VERSION              0x05

#define AUTH_VERSION                0x01

#define AUTH_STATUS_SUCCESS         0x00
#define AUTH_STATUS_FAILURE         0x01

#define NOAUTH                      0x00
#define USERPASS                    0x02
#define NO_ACCEPTABLE_METHODS       0XFF

#define AUTH USERPASS

#define AUTH_RESPONSE_SIZE          2

#define DNS_STATE_IDLE              0
#define DNS_STATE_IN_PROGRESS       1
#define DNS_STATE_COMPLETED         2
#define DNS_STATE_ERROR            -1

#define GETADDRINFO_ELEMENTS        1

#define PORT_HIGH_BYTE_SHIFT        8
#define BYTE_MASK                   0xFF
#define RECV_FLAGS_DEFAULT          0
#define SETSOCKOPT_ENABLE           1
#define INVALID_FD                  -1

#define DOMAIN_LENGTH_OFFSET        1

#define PARSER_CHAR_RANGE_MAX       0xFF
#define STRING_TERMINATOR_SIZE      1

#endif