#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Server/ManagementProtocol/management.h"

#define DEFAULT_MGMT_HOST "127.0.0.1"
#define DEFAULT_MGMT_PORT 8080
#define RESPONSE_BUFFER_SIZE 1024
// Comandos del protocolo de management
#define MANAGEMENT_VERSION 0x01
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

typedef struct {
    int socket_fd;
    char server_host[256];
    int server_port;
    int authenticated;
} mgmt_client_t;


void mgmt_handle_disconnection(mgmt_client_t *client) {
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1; // Marcar el socket como inválido
    }
    if (client->authenticated) {
        printf("\n[ERROR] Connection to the management server was lost.\n");
    }
    client->authenticated = 0; // Requerir re-autenticación
}

// Enviar comando al servidor
int send_mgmt_command(mgmt_client_t *client, uint8_t cmd, const char *payload) {
    uint8_t payload_len = payload ? strlen(payload) : 0;
    
    // Construir mensaje: [VER][CMD][LEN][PAYLOAD]
    uint8_t message[259]; // 3 + 255 max payload + 1
    message[0] = MANAGEMENT_VERSION;
    message[1] = cmd;
    message[2] = payload_len;
    
    int total_len = 3;
    if (payload_len > 0) {
        memcpy(message + 3, payload, payload_len);
        total_len += payload_len;
    }

    ssize_t sent = send(client->socket_fd, message, total_len, MSG_NOSIGNAL);

    if (sent != total_len) {
        perror("Error sending command");
        mgmt_handle_disconnection(client); // Manejar la desconexión
        return -1;
    }
    
    return 0;
}

// Recibir respuesta del servidor
int recv_mgmt_response(mgmt_client_t *client, uint8_t *status, char *response_data, size_t max_len) {
    uint8_t header[3];
    
    // Recibir header: [VER][STATUS][LEN]
    ssize_t received = recv(client->socket_fd, header, 3, 0);
    if (received <= 0) {
        if (received == 0) {
            printf("Server closed the connection unexpectedly.\n");
        } else {
            perror("Error receiving response header");
        }
        mgmt_handle_disconnection(client);
        return -1;
    }
    if (received != 3) {
        perror("Error receiving response header");
        return -1;
    }
    
    if (header[0] != MANAGEMENT_VERSION) {
        printf("Invalid response version: 0x%02x\n", header[0]);
        return -1;
    }
    
    *status = header[1];
    uint8_t payload_len = header[2];
    
    if (payload_len > 0) {
        if (payload_len >= max_len) {
            printf("Response too large: %d bytes\n", payload_len);
            return -1;
        }
        
        received = recv(client->socket_fd, response_data, payload_len, 0);
        if (received != payload_len) {
            perror("Error receiving response payload");
            return -1;
        }
        response_data[payload_len] = '\0';
    } else {
        response_data[0] = '\0';
    }
    
    return 0;
}

// Conectar al servidor
int mgmt_connect(mgmt_client_t *client) {
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        perror("Error creating socket");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(client->server_port);
    
    if (inet_pton(AF_INET, client->server_host, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(client->socket_fd);
        return -1;
    }
    
    if (connect(client->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(client->socket_fd);
        return -1;
    }
    
    printf("Connected to management server %s:%d\n", client->server_host, client->server_port);
    return 0;
}

// Autenticar con el servidor
int mgmt_authenticate(mgmt_client_t *client, const char *username, const char *password) {
    if (strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN) {
        printf( "Username/password must be smaller or equal than %d characters\n", MAX_USERNAME_LEN);
        return -1;
    }

    char credentials[512];
    snprintf(credentials, sizeof(credentials), "%s:%s", username, password);
    
    if (send_mgmt_command(client, CMD_AUTH, credentials) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    if (status == STATUS_OK) {
        printf("Authentication successful: %s\n", response);
        client->authenticated = 1;
        return 0;
    } else {
        printf("Authentication failed: %s\n", response);
        return -1;
    }
}

// Obtener estadísticas
int mgmt_get_stats(mgmt_client_t *client) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    
    if (send_mgmt_command(client, CMD_STATS, NULL) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    printf("Server Statistics:\n%s\n", response);
    return 0;
}

// Listar usuarios
int mgmt_list_users(mgmt_client_t *client) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    
    if (send_mgmt_command(client, CMD_LIST_USERS, NULL) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    printf("%s\n", response);
    return 0;
}

// Agregar usuario
int mgmt_add_user(mgmt_client_t *client, const char *username, const char *password) {

    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    if (strlen(username) > MAX_USERNAME_LEN || strlen(password) > MAX_PASSWORD_LEN) {
        printf( "Username/password must be smaller or equal than %d characters\n", MAX_USERNAME_LEN);
        return -1;
    }
    
    char user_data[512];
    snprintf(user_data, sizeof(user_data), "%s:%s", username, password);
    
    if (send_mgmt_command(client, CMD_ADD_USER, user_data) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    if (status == STATUS_OK) {
        printf("Success: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
    return status == STATUS_OK ? 0 : -1;
}

// Eliminar usuario
int mgmt_delete_user(mgmt_client_t *client, const char *username) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    if (strlen(username) > MAX_USERNAME_LEN ) {
        printf( "Username must be smaller or equal than %d characters\n", MAX_USERNAME_LEN);
        return -1;
    }
    
    if (send_mgmt_command(client, CMD_DELETE_USER, username) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    if (status == STATUS_OK) {
        printf("Success: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
    return status == STATUS_OK ? 0 : -1;
}

// Cambiar contraseña de usuario
int mgmt_change_password(mgmt_client_t *client, const char *username, const char *new_password) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    if (strlen(username) > MAX_USERNAME_LEN || strlen(new_password) > MAX_PASSWORD_LEN) {
        printf( "Username/password must be smaller or equal than %d characters\n", MAX_USERNAME_LEN);
        return -1;
    }
    char payload[512];
    snprintf(payload, sizeof(payload), "%s:%s", username, new_password);
    if (send_mgmt_command(client, CMD_CHANGE_PASSWORD, payload) < 0) {
        return -1;
    }
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    if (status == STATUS_OK) {
        printf("Success: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
    return status == STATUS_OK ? 0 : -1;
}

// Obtener información del buffer
int mgmt_get_buffer_info(mgmt_client_t *client) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    
    if (send_mgmt_command(client, CMD_GET_BUFFER_INFO, NULL) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    printf("Buffer Information:\n%s\n", response);
    return 0;
}

// Cambiar tamaño del buffer
int mgmt_set_buffer_size(mgmt_client_t *client, const char *buffer_size_str) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    
    if (send_mgmt_command(client, CMD_SET_BUFFER_SIZE, buffer_size_str) < 0) {
        return -1;
    }
    
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }
    
    if (status == STATUS_OK) {
        printf("Success: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
    return status == STATUS_OK ? 0 : -1;
}

void mgmt_set_auth_method(mgmt_client_t *client, char * method) {
    if(!client->authenticated) {
        printf("Not authenticated\n");
        return;
    }
    if (send_mgmt_command(client, CMD_SET_AUTH_METHOD, method) < 0) {
        return;
    }
    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return;
    }
    if (status == STATUS_OK) {
        printf("Success: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
}

int mgmt_get_auth_method(mgmt_client_t *client) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }

    if (send_mgmt_command(client, CMD_GET_AUTH_METHOD, NULL) < 0) {
        return -1;
    }

    uint8_t status;
    char response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof(response)) < 0) {
        return -1;
    }

    if (status == STATUS_OK) {
        printf("Current Authentication Method: %s\n", response);
    } else {
        printf("Error: %s\n", response);
    }
    return status == STATUS_OK ? 0 : -1;
    }

int mgmt_get_log_by_user(mgmt_client_t *client, const char *username) {
    if (!client->authenticated) {
        printf("Not authenticated\n");
        return -1;
    }
    if (strlen(username) > MAX_USERNAME_LEN) {
        printf("Username must be ≤ %d characters\n", MAX_USERNAME_LEN);
        return -1;
    }

    if (send_mgmt_command(client, CMD_GET_LOG_BY_USER, username) < 0)
        return -1;

    uint8_t status;
    char    response[RESPONSE_BUFFER_SIZE];
    if (recv_mgmt_response(client, &status, response, sizeof response) < 0)
        return -1;

    if (status == STATUS_OK) {
        /* La respuesta puede contener saltos de línea ya formateados */
        printf("Access log for %s:\n%s\n", username, response);
        return 0;
    }
    printf("Error: %s\n", response);
    return -1;
}


// Desconectar
void mgmt_disconnect(mgmt_client_t *client) {
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    client->authenticated = 0;
}

void interactive_menu(mgmt_client_t *client) {
    char input[512];
    char username[256], password[256];

    while (1) {
        printf("\n=== Management Client ===\n");

        if (!client->authenticated) {
            // --- MENÚ DESCONECTADO ---
            printf("Status: Not Connected\n");
            printf("1. Connect and Authenticate\n");
            printf("2. Exit\n");
            printf("Choice: ");

            if (!fgets(input, sizeof(input), stdin)) { break; }
            int choice = atoi(input);

            if (choice == 1) {
                if (mgmt_connect(client) < 0) {
                    printf("Could not connect to the server. Please try again later.\n");
                    continue;
                }

                printf("Username: ");
                if (!fgets(username, sizeof(username), stdin)) { break; }
                username[strcspn(username, "\n")] = 0;

                printf("Password: ");
                if (!fgets(password, sizeof(password), stdin)) { break; }
                password[strcspn(password, "\n")] = 0;

                if (mgmt_authenticate(client, username, password) != 0) {
                    printf("Authentication failed. Please check credentials or server status.\n");
                } else {
                    printf("Authentication successful!\n");
                }
            } else if (choice == 2) {
                printf("Exiting...\n");
                break;
            } else {
                printf("Invalid choice.\n");
            }
        } else {
            // --- MENÚ AUTENTICADO ---
            printf("Status: Authenticated\n");
            printf("1. Get Statistics\n");
            printf("2. List Users\n");
            printf("3. Add User\n");
            printf("4. Delete User\n");
            printf("5. Change User Password\n");
            printf("6. Get Buffer Info\n");
            printf("7. Set Buffer Size\n");
            printf("8. Change Authentication Method\n");
            printf("9. Show Current Authentication Method\n");
            printf("10. Show user logs\n");
            printf("11. Disconnect\n");
            printf("Choice: ");

            if (!fgets(input, sizeof(input), stdin)) { break; }
            int choice = atoi(input);

            switch (choice) {
                case 1: mgmt_get_stats(client); break;
                case 2: mgmt_list_users(client); break;
                case 3:
                    printf("New username: ");
                    if (fgets(username, sizeof(username), stdin)) {
                        username[strcspn(username, "\n")] = 0;
                    }
                    printf("New password: ");
                    if (fgets(password, sizeof(password), stdin)) {
                        password[strcspn(password, "\n")] = 0;
                    }
                    mgmt_add_user(client, username, password);
                    break;
                case 4:
                    printf("Username to delete: ");
                    if (fgets(username, sizeof(username), stdin)) {
                        username[strcspn(username, "\n")] = 0;
                    }
                    mgmt_delete_user(client, username);
                    break;
                case 5:
                    printf("Username to change password: ");
                    if (fgets(username, sizeof(username), stdin)) {
                        username[strcspn(username, "\n")] = 0;
                    }
                    printf("New password: ");
                    if (fgets(password, sizeof(password), stdin)) {
                        password[strcspn(password, "\n")] = 0;
                    }
                    mgmt_change_password(client, username, password);
                    break;
                case 6: mgmt_get_buffer_info(client); break;
                case 7:
                    printf("New buffer size (4096, 8192, 16384, 32768, 65536, 131072): ");
                    if (fgets(username, sizeof(username), stdin)) {
                        username[strcspn(username, "\n")] = 0;
                    }
                    mgmt_set_buffer_size(client, username);
                    break;
                case 8:
                    printf("Select an authentication method:\n");
                    printf("1. No Authentication\n2. Password Authentication\nChoice: ");
                    if (fgets(input, sizeof(input), stdin)) {
                        int auth_choice = atoi(input);
                        if (auth_choice == 1) mgmt_set_auth_method(client, "NOAUTH");
                        else if (auth_choice == 2) mgmt_set_auth_method(client, "AUTH");
                        else printf("Invalid choice.\n");
                    }
                    break;
                case 9: mgmt_get_auth_method(client); break;
                case 10:
                    printf("Username (use \"anonymous\" for NOAUTH): ");
                    if (fgets(username, sizeof(username), stdin)) {
                        username[strcspn(username, "\n")] = 0;
                    }
                    mgmt_get_log_by_user(client, username);
                    break;
                case 11:
                    printf("Disconnecting...\n");
                    mgmt_disconnect(client);
                    break;
                default:
                    printf("Invalid choice\n");
                    break;
            }
        }
    }
}


int main(int argc, char *argv[]) {
    mgmt_client_t client = {0};
    
    // Valores por defecto
    strcpy(client.server_host, DEFAULT_MGMT_HOST);
    client.server_port = DEFAULT_MGMT_PORT;
    client.socket_fd = -1;
    client.authenticated = 0;
    
    // Parsear argumentos opcionales
    if (argc >= 2) {
        strcpy(client.server_host, argv[1]);
    }
    if (argc >= 3) {
        client.server_port = atoi(argv[2]);
    }
    
    printf("Management Protocol Client\n");
    printf("Connecting to %s:%d\n", client.server_host, client.server_port);
    
    if (mgmt_connect(&client) < 0) {
        exit(1);
    }
    
    interactive_menu(&client);
    
    mgmt_disconnect(&client);
    printf("Client disconnected.\n");
    
    return 0;
}