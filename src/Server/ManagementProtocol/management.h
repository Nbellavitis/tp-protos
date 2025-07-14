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
#include "management_cmds.h"




#define ADMIN_DEFAULT_USER "admin"
#define ADMIN_DEFAULT_PASSWORD "admin123"
#define ADMIN_USER_ENV_VAR "ADMIN_USERNAME"
#define ADMIN_PASSWORD_ENV_VAR "ADMIN_PASSWORD"


// Management protocol constants
#define MAX_USERNAME_LEN        63
#define MAX_PASSWORD_LEN        63
#define MAX_MGMT_PAYLOAD_LEN    255

// Management response buffer sizes  
#define MGMT_RESPONSE_SIZE              256
#define MGMT_EXTENDED_RESPONSE_SIZE     512
#define MGMT_PAYLOAD_SIZE               256
#define STATS_RESPONSE_SIZE             512
#define USERS_RESPONSE_SIZE             1024

// Buffer size list for management responses
#define AVAILABLE_BUFFER_SIZES_STR      "4096, 8192, 16384, 32768, 65536, 131072"


#define MANAGEMENT_VERSION 0x01
#define MANAGEMENT_BUFFER_SIZE 4096

// Comandos del protocolo
#define CMD_AUTH 0x01
#define CMD_STATS 0x02
#define CMD_LIST_USERS 0x03
#define CMD_ADD_USER 0x04
#define CMD_DELETE_USER 0x05
#define CMD_CHANGE_PASSWORD 0x06
#define CMD_SET_BUFFER_SIZE 0x07
#define CMD_GET_BUFFER_INFO 0x08
#define CMD_SET_AUTH_METHOD 0x09
#define CMD_GET_AUTH_METHOD 0x0A
#define CMD_GET_LOG_BY_USER 0x0B

// Status codes
#define STATUS_OK 0x00
#define STATUS_ERROR 0x01
#define STATUS_AUTH_REQUIRED 0x02
#define STATUS_AUTH_FAILED 0x03
#define STATUS_NOT_FOUND 0x04
#define STATUS_FULL 0x05

#define STATUS_INVALID_FORMAT   0x06
#define STATUS_LEN_EXCEEDED     0x07
#define STATUS_ALREADY_EXISTS   0x08
#define STATUS_NOT_ALLOWED      0x09
#define STATUS_RESERVED_USER 0x0A


#define STATS_FIELDS          5
#define STATS_PAYLOAD_BYTES  (STATS_FIELDS * sizeof(uint32_t))

static const uint32_t buffer_sizes[] = {4096, 8192, 16384, 32768, 65536, 131072};
#define BUFFER_SIZE_CNT   ((uint8_t)(sizeof(buffer_sizes) / sizeof(buffer_sizes[0])))
#define BUFFER_SIZE_MIN   (buffer_sizes[0])
#define BUFFER_SIZE_MAX   (buffer_sizes[BUFFER_SIZE_CNT-1])



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