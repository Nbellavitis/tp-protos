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

// Declaraciones de funciones externas
extern struct users* get_authorized_users(void);
extern int get_num_authorized_users(void);
extern bool add_user(const char* username, const char* password);
extern bool delete_user(const char* username);
extern bool change_user_password(const char* username, const char* new_password);

// Credenciales hardcodeadas del admin
static char* ADMIN_USERNAME = ADMIN_DEFAULT_USER;
static char* ADMIN_PASSWORD = ADMIN_DEFAULT_PASSWORD;

// Handlers del selector
static void management_read(struct selector_key *key);
static void management_write(struct selector_key *key);
static void management_close(struct selector_key *key);

static fd_handler management_handler = {
        .handle_read = management_read,
        .handle_write = management_write,
        .handle_close = management_close,
};

// Handler dummy para estados que no procesan lectura
static unsigned mgmt_dummy_read_handler(struct selector_key *key) {
    LOG_DEBUG("mgmt_dummy_read_handler: Unexpected read event in current state");
    return MGMT_ERROR; // Transición a estado de error
}

// Definición de la máquina de estados
static const struct state_definition management_states[] = {
        {.state = MGMT_AUTH_READ, .on_arrival = mgmt_auth_read_init, .on_read_ready = mgmt_auth_read},
        {.state = MGMT_AUTH_WRITE, .on_write_ready = mgmt_auth_write, .on_read_ready = mgmt_dummy_read_handler},
        {.state = MGMT_COMMAND_READ, .on_arrival = mgmt_command_read_init, .on_read_ready = mgmt_command_read},
        {.state = MGMT_COMMAND_WRITE, .on_write_ready = mgmt_command_write, .on_read_ready = mgmt_dummy_read_handler},
        {.state = MGMT_CLOSED, .on_arrival = mgmt_closed_arrival, .on_read_ready = mgmt_dummy_read_handler},
        {.state = MGMT_ERROR, .on_arrival = mgmt_error_arrival, .on_read_ready = mgmt_dummy_read_handler}
};

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

    if (new_client_socket < 0) {
        perror("Error accepting management connection");
        return;
    }

    if (new_client_socket >= FD_SETSIZE) {
        LOG_ERROR("Management client socket exceeds maximum file descriptor limit");
        close(new_client_socket);
        return;
    }

    ManagementData* mgmt_data = calloc(1, sizeof(ManagementData));
    if (mgmt_data == NULL) {
        perror("Error allocating memory for management data");
        close(new_client_socket);
        return;
    }

    LOG_INFO("New management client connected: %d", new_client_socket);

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
    ManagementData *mgmt_data = (ManagementData *)key->data;
    stm_handler_close(&mgmt_data->stm, key);
    close_management_connection(key);
}

void close_management_connection(struct selector_key *key) {
    ManagementData *mgmt_data = (ManagementData *)key->data;
    if (mgmt_data->closed) {
        return;
    }

    mgmt_data->closed = true;
    LOG_INFO("Closing management connection: %d", mgmt_data->client_fd);

    if (mgmt_data->client_fd >= 0) {
        selector_unregister_fd(key->s, mgmt_data->client_fd);
        close(mgmt_data->client_fd);
    }
    free(mgmt_data);
}

// Parser functions
void init_management_parser(management_parser *parser) {
    parser->version = 0;
    parser->command = 0;
    parser->payload_len = 0;
    parser->payload_offset = 0;
    parser->error = false;
    parser->complete = false;
    memset(parser->payload, 0, sizeof(parser->payload));
}

bool parse_management_command(management_parser *parser, struct buffer *buffer) {
    while (buffer_can_read(buffer) && !parser->complete && !parser->error) {
        uint8_t byte = buffer_read(buffer);

        if (parser->version == 0) {
            if (byte != MANAGEMENT_VERSION) {
                parser->error = true;
                LOG_ERROR("Invalid management version: 0x%02x", byte);
                return false;
            }
            parser->version = byte;
        } else if (parser->command == 0) {
            parser->command = byte;
        } else if (parser->payload_len == 0 && parser->payload_offset == 0) {
            parser->payload_len = byte;
            if (parser->payload_len == 0) {
                parser->complete = true;
                return true;
            }
        } else if (parser->payload_offset < parser->payload_len) {
            parser->payload[parser->payload_offset++] = byte;
            if (parser->payload_offset == parser->payload_len) {
                parser->payload[parser->payload_offset] = '\0';
                parser->complete = true;
                return true;
            }
        }
    }

    return parser->complete;
}

bool send_management_response(struct buffer *buffer, uint8_t status, const char *payload) {

    uint8_t payload_len = payload ? strlen(payload) : 0;
    size_t total_bytes_needed = 3 + payload_len; // version + status + len + payload

    size_t available_bytes;
    buffer_write_ptr(buffer, &available_bytes);

    if (available_bytes < total_bytes_needed) {
        return false; // Not enough space in buffer
    }


    buffer_write(buffer, MANAGEMENT_VERSION);
    buffer_write(buffer, status);

    buffer_write(buffer, payload_len);

    if (payload_len > 0) {
        for (int i = 0; i < payload_len; i++) {
            buffer_write(buffer, payload[i]);
        }
    }

    return true;
}

// State handlers
void mgmt_auth_read_init(unsigned state, struct selector_key *key) {
    LOG_DEBUG("Management: Starting authentication");
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

                if (strcmp(username, ADMIN_USERNAME) == 0 && strcmp(password, ADMIN_PASSWORD) == 0) {
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
        return MGMT_CLOSED;
    }
}

void mgmt_command_read_init(unsigned state, struct selector_key *key) {
    LOG_DEBUG("Management: Ready for commands");
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

        // Procesar comando
        switch (mgmt_data->parser.command) {
            case CMD_STATS: {
                char stats_response[512];
                snprintf(stats_response, sizeof(stats_response),
                         "Connections opened: %u\nConnections closed: %u\nClient bytes: %u\nOrigin bytes: %u",
                         stats_get_connections_opened(),
                         stats_get_connections_closed(),
                         stats_get_client_bytes(),
                         stats_get_origin_bytes());
                send_management_response(&mgmt_data->response_buffer, STATUS_OK, stats_response);
                break;
            }
            case CMD_LIST_USERS: {
                char users_response[1024] = "Users:\n";
                struct users* users = get_authorized_users();
                int num_users = get_num_authorized_users();

                for (int i = 0; i < num_users; i++) {
                    if (users[i].name != NULL) {
                        char user_line[128];
                        snprintf(user_line, sizeof(user_line), "- %s\n", users[i].name);
                        strcat(users_response, user_line);
                    }
                }

                if (num_users == 0) {
                    strcat(users_response, "No users configured");
                }

                send_management_response(&mgmt_data->response_buffer, STATUS_OK, users_response);
                break;
            }
            case CMD_ADD_USER: {
                // Parsear payload (formato: "username:password")
                char *colon = strchr(mgmt_data->parser.payload, ':');
                if (colon == NULL) {
                    send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Invalid format. Use: username:password");
                } else {
                    *colon = '\0';
                    char *username = mgmt_data->parser.payload;
                    char *password = colon + 1;

                    if (strlen(username) == 0 || strlen(password) == 0) {
                        send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Username and password cannot be empty");
                    } else if (add_user(username, password)) {
                        char response[256];
                        snprintf(response, sizeof(response), "User '%s' added successfully", username);
                        send_management_response(&mgmt_data->response_buffer, STATUS_OK, response);
                    } else {
                        if (get_num_authorized_users() >= MAX_USERS) {
                            send_management_response(&mgmt_data->response_buffer, STATUS_FULL, "Maximum number of users reached");
                        } else {
                            send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "User already exists or memory error");
                        }
                    }
                }
                break;
            }
            case CMD_DELETE_USER: {
                // El payload contiene solo el nombre de usuario a eliminar
                char *username = mgmt_data->parser.payload;

                if (strlen(username) == 0) {
                    send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Username cannot be empty");
                } else if (delete_user(username)) {
                    char response[256];
                    snprintf(response, sizeof(response), "User '%s' deleted successfully", username);
                    send_management_response(&mgmt_data->response_buffer, STATUS_OK, response);
                } else {
                    send_management_response(&mgmt_data->response_buffer, STATUS_NOT_FOUND, "User not found");
                }
                break;
            }
            case CMD_CHANGE_PASSWORD: {
                // Payload: "usuario:nueva_contraseña"
                char *colon = strchr(mgmt_data->parser.payload, ':');
                if (colon == NULL) {
                    send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Invalid format. Use: username:newpassword");
                } else {
                    *colon = '\0';
                    char *username = mgmt_data->parser.payload;
                    char *new_password = colon + 1;
                    if (strlen(username) == 0 || strlen(new_password) == 0) {
                        send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Username and new password cannot be empty");
                    } else if (change_user_password(username, new_password)) {
                        char response[256];
                        snprintf(response, sizeof(response), "Password changed for user '%s'", username);
                        send_management_response(&mgmt_data->response_buffer, STATUS_OK, response);
                    } else {
                        send_management_response(&mgmt_data->response_buffer, STATUS_NOT_FOUND, "User not found");
                    }
                }
                break;
            }
            case CMD_AUTH: {
                send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Invalid operation: already authenticated");
                break;
            };
            default:
                send_management_response(&mgmt_data->response_buffer, STATUS_ERROR, "Unknown command");
                break;
        }

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

void mgmt_closed_arrival(unsigned state, struct selector_key *key) {
    LOG_DEBUG("Management connection closed");
}

void mgmt_error_arrival(unsigned state, struct selector_key *key) {
    LOG_ERROR("Management connection error");
}