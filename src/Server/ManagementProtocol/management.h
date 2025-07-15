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
#include "../main.h"
#include "../users.h"
#include "../protocol_constants.h"
#include "../../management_constants.h"
#include "management_cmds.h"


static const uint32_t buffer_sizes[] = {4096, 8192, 16384, 32768, 65536, 131072};


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
bool send_management_response_raw(struct buffer *buffer,
                                  uint8_t         status,
                                  const uint8_t  *payload,
                                  uint8_t         payload_len);
bool change_user_password(const char* username, const char* new_password);

// Buffer size management
extern size_t get_current_buffer_size(void);
extern bool set_buffer_size(size_t new_size);
extern size_t get_available_buffer_sizes(void);

void mgtm_init_admin();

#endif //TP_PROTOS_MANAGEMENT_H