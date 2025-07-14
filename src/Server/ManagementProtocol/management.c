//
// Created by lulos on 6/27/2025.
//

#include "management.h"
#include "../Statistics/statistics.h"
#include "../args.h"
#include "../../logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bits/types/struct_tm.h>
#include <time.h>

// Declaraciones de funciones externas

// Credenciales hardcodeadas del admin
static const char* ADMIN_USERNAME = ADMIN_DEFAULT_USER;
static const char* ADMIN_PASSWORD = ADMIN_DEFAULT_PASSWORD;

// Handlers del selector
static void management_read(struct selector_key *key);
static void management_write(struct selector_key *key);
static void management_close(struct selector_key *key);


static fd_handler management_handler = {
        .handle_read = management_read,
        .handle_write = management_write,
        .handle_close = management_close,
};



// Definición de la máquina de estados
static const struct state_definition management_states[] = {
        {.state = MGMT_AUTH_READ, .on_arrival = mgmt_auth_read_init, .on_read_ready = mgmt_auth_read},
        {.state = MGMT_AUTH_WRITE, .on_write_ready = mgmt_auth_write},
        {.state = MGMT_COMMAND_READ, .on_arrival = mgmt_command_read_init, .on_read_ready = mgmt_command_read},
        {.state = MGMT_COMMAND_WRITE, .on_write_ready = mgmt_command_write},
        {.state = MGMT_CLOSED, .on_arrival = mgmt_closed_arrival},
        {.state = MGMT_ERROR, .on_arrival = mgmt_error_arrival}
};

static void cleanup_management_connection(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    if (mgmt_data != NULL && !mgmt_data->closed) {
        LOG_INFO("Cleaning up resources for management connection: %d", mgmt_data->client_fd);

        if (mgmt_data->client_fd >= 0) {
            close(mgmt_data->client_fd);
        }
        free(mgmt_data);
        key->data = NULL; // Buena práctica para evitar usar punteros inválidos
        mgmt_data->closed = true; // Prevenir doble liberación
    }
}


void mgtm_init_admin() {
    const char *env_user = getenv(ADMIN_USER_ENV_VAR);
    const char *env_pass = getenv(ADMIN_PASSWORD_ENV_VAR);

    ADMIN_USERNAME = (env_user != NULL) ? env_user : ADMIN_DEFAULT_USER;
    ADMIN_PASSWORD = (env_pass != NULL) ? env_pass : ADMIN_DEFAULT_PASSWORD;
}


void management_passive_accept(struct selector_key* key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int new_client_socket = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (selector_fd_set_nio(new_client_socket) == -1) {
        LOG_ERROR("Failed to set non-blocking mode for management client socket");
        close(new_client_socket);
        return;
    }
    if (new_client_socket < 0) {
        perror("Error accepting management connection");
        return;
    }

    if (new_client_socket >= FD_SETSIZE) {
        LOG_ERROR("%s" ,"Management client socket exceeds maximum file descriptor limit");
        close(new_client_socket);
        return;
    }

    ManagementData* mgmt_data = calloc(1, sizeof(ManagementData));
    if (mgmt_data == NULL) {
        perror("Error allocating memory for management data");
        close(new_client_socket);
        return;
    }

    LOG_DEBUG("New management client connected in socket %d", new_client_socket);

    // Inicializar estructura
    mgmt_data->stm.initial = MGMT_AUTH_READ;
    mgmt_data->stm.max_state = MGMT_ERROR;
    mgmt_data->stm.states = management_states;
    mgmt_data->closed = false;
    mgmt_data->authenticated = false;
    mgmt_data->client_fd = new_client_socket;

    buffer_init(&mgmt_data->client_buffer, MANAGEMENT_BUFFER_SIZE, mgmt_data->in_client_buffer);
    buffer_init(&mgmt_data->response_buffer, MANAGEMENT_BUFFER_SIZE, mgmt_data->in_response_buffer);

    init_management_parser(&mgmt_data->parser);
    stm_init(&mgmt_data->stm);

    selector_status ss = selector_register(key->s, new_client_socket, &management_handler, OP_READ, mgmt_data);
    if (ss != SELECTOR_SUCCESS) {
        free(mgmt_data);
        close(new_client_socket);
        return;
    }
}

static void management_read(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    LOG_DEBUG("Management read on socket %d", key->fd);

    const enum management_state state = stm_handler_read(&mgmt_data->stm, key);
    if (state == MGMT_ERROR || state == MGMT_CLOSED) {
        close_management_connection(key);
        return;
    }
}

static void management_write(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    LOG_DEBUG("Management write on socket %d", key->fd);

    const enum management_state state = stm_handler_write(&mgmt_data->stm, key);
    if (state == MGMT_ERROR || state == MGMT_CLOSED) {
        close_management_connection(key);
        return;
    }
}

static void management_close(struct selector_key *key) {
    cleanup_management_connection(key);
}
void close_management_connection(struct selector_key *key) {
    ManagementData *md = key->data;
    if (md != NULL && !md->closed) {
        selector_unregister_fd(key->s, key->fd);
    }
}

// Parser functions
void init_management_parser(management_parser *p)
{
    p->version          = 0;
    p->command          = 0;
    p->payload_len      = 0;
    p->payload_offset   = 0;
    p->len_bytes_read   = 0;
    p->error            = false;
    p->complete         = false;
    memset(p->payload, 0, sizeof p->payload);
}
bool parse_management_command(management_parser *p, struct buffer *b)
{
    while (buffer_can_read(b) && !p->complete && !p->error) {
        uint8_t byte = buffer_read(b);

        if (p->version == 0) {                    /* VER */
            if (byte != MANAGEMENT_VERSION) {
                p->error = true;
                LOG_ERROR("Invalid management version 0x%02X", byte);
                return false;
            }
            p->version = byte;
        } else if (p->command == 0) {             /* CMD */
            p->command = byte;
        } else if (p->len_bytes_read < LEN_BYTES) {       /* LEN‑hi LEN‑lo */
            if (p->len_bytes_read == 0) p->payload_len  = (uint16_t)byte << 8;
            else                         p->payload_len |= byte;
            p->len_bytes_read++;
            if (p->len_bytes_read == LEN_BYTES && p->payload_len == 0) {
                p->complete = true;
                return true;
            }
        } else {                                  /* PAYLOAD */
            if (p->payload_offset < MAX_MGMT_PAYLOAD_LEN)
                p->payload[p->payload_offset] = byte; /* se trunca si >max   */
            p->payload_offset++;
            if (p->payload_offset == p->payload_len) {

                uint16_t len = p->payload_len < MAX_MGMT_PAYLOAD_LEN ? p->payload_len:MAX_MGMT_PAYLOAD_LEN;

                p->payload[len] = '\0';
                p->complete = true;
                return true;
            }
        }
    }
    return p->complete;
}


// State handlers
void mgmt_auth_read_init(unsigned state __attribute__((unused)), struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;
    init_management_parser(&mgmt_data->parser);
}

unsigned mgmt_auth_read(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    size_t read_limit;
    uint8_t *buffer_ptr = buffer_write_ptr(&mgmt_data->client_buffer, &read_limit);
    if (read_limit == 0) {
        // Buffer full, compact and try again
        buffer_compact(&mgmt_data->client_buffer);
        buffer_ptr = buffer_write_ptr(&mgmt_data->client_buffer, &read_limit);
        if (read_limit == 0) {
            return MGMT_ERROR; // Still no space after compacting
        }
    }
    ssize_t read_count = recv(key->fd, buffer_ptr, read_limit, 0);

    if (read_count <= 0) {
        return MGMT_ERROR;
    }

    buffer_write_adv(&mgmt_data->client_buffer, read_count);

    if (parse_management_command(&mgmt_data->parser, &mgmt_data->client_buffer)) {
        if (mgmt_data->parser.error) {
            return MGMT_ERROR;
        }

        if (mgmt_data->parser.command != CMD_AUTH) {
            send_management_response(&mgmt_data->response_buffer, STATUS_AUTH_REQUIRED, "Authentication required");
        } else {
            // Parsear credenciales del payload (formato: "username:password")
            char *colon = strchr(mgmt_data->parser.payload, ':');
            if (colon == NULL) {
                send_management_response(&mgmt_data->response_buffer, STATUS_AUTH_FAILED, "Invalid credentials format");
            } else {
                *colon = '\0';
                char *username = mgmt_data->parser.payload;
                char *password = colon + 1;

                if(strlen(username) > MAX_USERNAME_LEN || strlen(ADMIN_PASSWORD) > MAX_PASSWORD_LEN){
                    send_management_response(&mgmt_data->response_buffer, STATUS_AUTH_FAILED, "Username or password length is longer than allowed");
                }
                else if (strcmp(username, ADMIN_USERNAME) == 0 && strcmp(password, ADMIN_PASSWORD) == 0) {
                    mgmt_data->authenticated = true;
                    send_management_response(&mgmt_data->response_buffer, STATUS_OK, "Authentication successful");
                    LOG_INFO("Management: Authentication successful for %s", username);
                } else {
                    send_management_response(&mgmt_data->response_buffer, STATUS_AUTH_FAILED, "Invalid credentials");
                    LOG_WARN("Management: Authentication failed for %s", username);
                }
            }
        }

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return MGMT_ERROR;
        }
        return MGMT_AUTH_WRITE;
    }

    return MGMT_AUTH_READ;
}

unsigned mgmt_auth_write(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    size_t read_limit;
    uint8_t *buffer_ptr = buffer_read_ptr(&mgmt_data->response_buffer, &read_limit);
    ssize_t write_count = send(key->fd, buffer_ptr, read_limit, MSG_NOSIGNAL);

    if (write_count <= 0) {
        return MGMT_ERROR;
    }

    buffer_read_adv(&mgmt_data->response_buffer, write_count);

    if (buffer_can_read(&mgmt_data->response_buffer)) {
        return MGMT_AUTH_WRITE;
    }

    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return MGMT_ERROR;
    }

    if (mgmt_data->authenticated) {
        return MGMT_COMMAND_READ;
    } else {
        // Allow multiple authentication attempts
        return MGMT_AUTH_READ;
    }
}

void mgmt_command_read_init(unsigned state __attribute__((unused)), struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;
    init_management_parser(&mgmt_data->parser);
}

unsigned mgmt_command_read(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    size_t read_limit;
    uint8_t *buffer_ptr = buffer_write_ptr(&mgmt_data->client_buffer, &read_limit);
    if (read_limit == 0) {
        // Buffer full, compact and try again
        buffer_compact(&mgmt_data->client_buffer);
        buffer_ptr = buffer_write_ptr(&mgmt_data->client_buffer, &read_limit);
        if (read_limit == 0) {
            return MGMT_ERROR; // Still no space after compacting
        }
    }
    ssize_t read_count = recv(key->fd, buffer_ptr, read_limit, 0);

    if (read_count <= 0) {
        return MGMT_ERROR;
    }

    buffer_write_adv(&mgmt_data->client_buffer, read_count);

    if (parse_management_command(&mgmt_data->parser, &mgmt_data->client_buffer)) {
        if (mgmt_data->parser.error) {
            return MGMT_ERROR;
        }

        mgmt_dispatch_command(mgmt_data);  //Procesar comando

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return MGMT_ERROR;
        }
        return MGMT_COMMAND_WRITE;
    }

    return MGMT_COMMAND_READ;
}

unsigned mgmt_command_write(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;

    size_t read_limit;
    uint8_t *buffer_ptr = buffer_read_ptr(&mgmt_data->response_buffer, &read_limit);
    ssize_t write_count = send(key->fd, buffer_ptr, read_limit, MSG_NOSIGNAL);

    if (write_count <= 0) {
        return MGMT_ERROR;
    }

    buffer_read_adv(&mgmt_data->response_buffer, write_count);

    if (buffer_can_read(&mgmt_data->response_buffer)) {
        return MGMT_COMMAND_WRITE;
    }

    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return MGMT_ERROR;
    }

    return MGMT_COMMAND_READ;
}

// TODO: no creo que tengan sentido estas funciones. Eliminar
void mgmt_closed_arrival(unsigned state __attribute__((unused)), struct selector_key *key __attribute__((unused))) {
    LOG_DEBUG("%s" ,"Management connection closed");
}

void mgmt_error_arrival(unsigned state __attribute__((unused)), struct selector_key *key __attribute__((unused))) {
    LOG_ERROR("%s" ,"Management connection error");
}




bool send_management_response_raw(struct buffer *buf, uint8_t status,
                                  const uint8_t *pl, uint16_t len)
{
    size_t avail;
    buffer_write_ptr(buf, &avail);
    if (len > MAX_MGMT_PAYLOAD_LEN || avail < 4 + len) return false;

    buffer_write(buf, MANAGEMENT_VERSION);
    buffer_write(buf, status);
    buffer_write(buf, (len >> 8) & 0xFF);         /* LEN‑hi */
    buffer_write(buf,  len        & 0xFF);        /* LEN‑lo */
    for (uint16_t i = 0; i < len; i++) buffer_write(buf, pl[i]);
    return true;
}

bool send_management_response(struct buffer *buf, uint8_t status,
                              const char *utf8)
{
    uint16_t len = (uint16_t)strnlen(utf8, MAX_MGMT_PAYLOAD_LEN);
    size_t   avail;
    buffer_write_ptr(buf, &avail);
    if (avail < 4 + len) return false;

    buffer_write(buf, MANAGEMENT_VERSION);
    buffer_write(buf, status);
    buffer_write(buf, (len >> 8) & 0xFF);
    buffer_write(buf,  len        & 0xFF);
    for (uint16_t i = 0; i < len; i++) buffer_write(buf, utf8[i]);
    return true;
}