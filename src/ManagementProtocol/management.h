//
// Created by lulos on 6/27/2025.
//

#ifndef TP_PROTOS_MANAGEMENT_H
#define TP_PROTOS_MANAGEMENT_H

#include "../selector.h"
#include "../stm.h"
#include "../buffer.h"
#include "../args.h"
#include <stdbool.h>
#include <stdint.h>

/*
CLIENTE → SERVIDOR                                             SERVIDOR → CLIENTE
+-----+-----+------+------+-------------------+      +-----+-------+ ---------------------------------+
| VER | CMD | payload len | Payload (opcional)|      |VER | STATUS | Payload len |Payload (opcional)  |
+-----+-----+------+------+-------------------+      +-----+-------+----------------------------------+
[1]     [1]       [1]        [0..255]                  [1]     [1]             [1]        [0..255]
 */

/*
 *    VER --> solo es valido 0x01
 *    CMD --> Valido de 0x01 hasta .... todo definir
 *    PAYLOAD LEN: Valido de 0x00 hasta 0xFF
 *    Payload: Son como mucho 255 caracteres. Depende del CMD.
 *
 *
 *    Va a por TCP y puede elegir entre usar o no usar Auth. (Negociacion)
 *
 */

#define MANAGEMENT_VERSION 0x01
#define MANAGEMENT_BUFFER_SIZE 4096

// Comandos del protocolo
#define CMD_AUTH 0x01
#define CMD_STATS 0x02
#define CMD_LIST_USERS 0x03
#define CMD_ADD_USER 0x04
#define CMD_DELETE_USER 0x05

// Status codes
#define STATUS_OK 0x00
#define STATUS_ERROR 0x01
#define STATUS_AUTH_REQUIRED 0x02
#define STATUS_AUTH_FAILED 0x03
#define STATUS_NOT_FOUND 0x04
#define STATUS_FULL 0x05

// Estados de la máquina de estados
enum management_state {
    MGMT_AUTH_READ = 0,
    MGMT_AUTH_WRITE,
    MGMT_COMMAND_READ,
    MGMT_COMMAND_WRITE,
    MGMT_CLOSED,
    MGMT_ERROR
};

// Parser para comandos
typedef struct {
    uint8_t version;
    uint8_t command;
    uint8_t payload_len;
    char payload[256];
    uint8_t payload_offset;
    bool error;
    bool complete;
} management_parser;

// Estructura de datos para conexiones de management
typedef struct ManagementData {
    struct state_machine stm;
    bool closed;
    bool authenticated;
    int client_fd;
    
    management_parser parser;
    
    struct buffer client_buffer;
    struct buffer response_buffer;
    
    uint8_t in_client_buffer[MANAGEMENT_BUFFER_SIZE];
    uint8_t in_response_buffer[MANAGEMENT_BUFFER_SIZE];
} ManagementData;

// Funciones de la máquina de estados
void management_passive_accept(struct selector_key* key);
void close_management_connection(struct selector_key *key);

// Handlers de estados
void mgmt_auth_read_init(unsigned state, struct selector_key *key);
unsigned mgmt_auth_read(struct selector_key *key);
unsigned mgmt_auth_write(struct selector_key *key);

void mgmt_command_read_init(unsigned state, struct selector_key *key);
unsigned mgmt_command_read(struct selector_key *key);
unsigned mgmt_command_write(struct selector_key *key);

void mgmt_closed_arrival(unsigned state, struct selector_key *key);
void mgmt_error_arrival(unsigned state, struct selector_key *key);

// Funciones del parser
void init_management_parser(management_parser *parser);
bool parse_management_command(management_parser *parser, struct buffer *buffer);

// Funciones de respuesta
bool send_management_response(struct buffer *buffer, uint8_t status, const char *payload);

#endif //TP_PROTOS_MANAGEMENT_H