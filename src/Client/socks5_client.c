#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <signal.h>
#include "client_utils.h"


volatile sig_atomic_t interrupted = 0;

void signal_handler(int sig) {
  
    interrupted = 1;
}


#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_VERSION 0x01
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define NOAUTH 0x00
#define USERPASS 0x02
#define AUTH_METHOD_FAIL 0xFF

#define SOCKS5_SUCCESS 0x00
#define SOCKS5_RESERVED 0x00
#define AUTH_SUCCESS 0x00

#define PROXY_HOST_BUFFER_SIZE 256
#define USERNAME_BUFFER_SIZE 256
#define PASSWORD_BUFFER_SIZE 256
#define AUTH_REQUEST_BUFFER_SIZE 512
#define CONNECT_REQUEST_BUFFER_SIZE 512
#define CONNECT_RESPONSE_BUFFER_SIZE 512
#define HTTP_REQUEST_BUFFER_SIZE 1024
#define HTTP_RESPONSE_BUFFER_SIZE 4096
#define INPUT_BUFFER_SIZE 512
#define TARGET_HOST_BUFFER_SIZE 256
#define PATH_BUFFER_SIZE 512

#define IPV4_ADDR_SIZE 4
#define IPV6_ADDR_SIZE 16
#define PORT_SIZE 2
#define SOCKS5_NEGOTIATION_RESPONSE_SIZE 2
#define SOCKS5_AUTH_RESPONSE_SIZE 2
#define SOCKS5_MIN_CONNECT_RESPONSE_SIZE 4

#define SINGLE_METHOD_COUNT 1
#define NEGOTIATION_REQUEST_SIZE 3

#define DEFAULT_HTTP_PORT 80

#define MENU_AUTHENTICATE 1
#define MENU_BASIC_TEST 2
#define MENU_CUSTOM_REQUEST 3
#define MENU_EXIT 4

#define MIN_ARGS_PROXY_HOST 2
#define MIN_ARGS_PROXY_PORT 3
#define MIN_ARGS_USERNAME 4
#define MIN_ARGS_PASSWORD 5

typedef struct {
    int socket_fd;
    char proxy_host[PROXY_HOST_BUFFER_SIZE];
    int proxy_port;
    char username[USERNAME_BUFFER_SIZE];
    char password[PASSWORD_BUFFER_SIZE];
    int authenticated;
} socks5_client_t;

int socks5_authenticate(socks5_client_t *client);

int socks5_connect_proxy(socks5_client_t *client) {
    return connect_server( client->proxy_host , client->proxy_port, &client->socket_fd);
}

int socks5_negotiate(socks5_client_t *client, int offer_auth) {
    uint8_t request[4];
    uint8_t response[SOCKS5_NEGOTIATION_RESPONSE_SIZE];

    request[0] = SOCKS5_VERSION;
    if (offer_auth) {
        request[1] = 1;
        request[2] = USERPASS;
    } else {
        request[1] = 1;
        request[2] = NOAUTH;
    }

    int req_len = NEGOTIATION_REQUEST_SIZE;

    if (send(client->socket_fd, request, req_len, 0) != req_len) {
        perror("[SOCKS5] Error sending negotiation request");
        return -1;
    }

    // Recibir respuesta del servidor
    ssize_t received = recv(client->socket_fd, response, SOCKS5_NEGOTIATION_RESPONSE_SIZE, 0);
    if (received != SOCKS5_NEGOTIATION_RESPONSE_SIZE) {
        printf("[SOCKS5] Error receiving negotiation response, got %ld bytes\n", received);
        if (received > 0) {
            printf("[SOCKS5] Received: [0x%02x]\n", response[0]);
        }
        return -1;
    }

    if (response[0] != SOCKS5_VERSION) {
        printf("[SOCKS5] Invalid SOCKS version in response: 0x%02x\n", response[0]);
        return -1;
    }

    uint8_t selected_method = response[1];

    if (selected_method == AUTH_METHOD_FAIL) {
        printf("[SOCKS5] No acceptable authentication method. Connection refused by server.\n");
        return -1;
    }

    if (selected_method == USERPASS) {
        int auth_result = socks5_authenticate(client);
        if (auth_result == 0) {
            return USERPASS;
        } else {
            return -1;
        }
    } else if (selected_method == NOAUTH) {
        return NOAUTH;
    } else {
        printf("[SOCKS5] Server selected unknown authentication method: 0x%02x\n", selected_method);
        return -1;
    }
}

// Autenticación username/password
int socks5_authenticate(socks5_client_t *client) {
    uint8_t request[AUTH_REQUEST_BUFFER_SIZE];
    uint8_t response[SOCKS5_AUTH_RESPONSE_SIZE];
    int pos = 0;
    
   
    
    request[pos++] = SOCKS5_AUTH_VERSION;
    request[pos++] = strlen(client->username);
    memcpy(request + pos, client->username, strlen(client->username));
    pos += strlen(client->username);
    request[pos++] = strlen(client->password);
    memcpy(request + pos, client->password, strlen(client->password));
    pos += strlen(client->password);
    
   
    
    if (send(client->socket_fd, request, pos, 0) != pos) {
        perror("[SOCKS5] Error sending authentication");
        return -1;
    }

  
    ssize_t received = recv(client->socket_fd, response, SOCKS5_AUTH_RESPONSE_SIZE, 0);
    if (received != SOCKS5_AUTH_RESPONSE_SIZE) {
        printf("[SOCKS5] Error receiving authentication response, got %ld bytes\n", received);
        return -1;
    }

    if (response[0] != SOCKS5_AUTH_VERSION) {
        printf("[SOCKS5] Invalid auth version in response: 0x%02x\n", response[0]);
        return -1;
    }
    
    if (response[1] != AUTH_SUCCESS) {
        printf("[SOCKS5] Authentication failed. Status: 0x%02x\n", response[1]);
        return -1;
    }

    return 0;
}

int socks5_connect_target(socks5_client_t *client, const char *target_host, int target_port) {
    uint8_t request[CONNECT_REQUEST_BUFFER_SIZE];
    uint8_t response[CONNECT_RESPONSE_BUFFER_SIZE];
    int pos = 0;
    

    request[pos++] = SOCKS5_VERSION;
    request[pos++] = SOCKS5_CMD_CONNECT;
    request[pos++] = SOCKS5_RESERVED;
    
    // Determinar tipo de dirección
    struct in_addr addr;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, target_host, &addr) == 1) {
        request[pos++] = SOCKS5_ATYP_IPV4;
        memcpy(request + pos, &addr, IPV4_ADDR_SIZE);
        pos += IPV4_ADDR_SIZE;
    } else if (inet_pton(AF_INET6, target_host, &addr6) == 1) {
        request[pos++] = SOCKS5_ATYP_IPV6;
        memcpy(request + pos, &addr6, IPV6_ADDR_SIZE);
        pos += IPV6_ADDR_SIZE;
    } else {
        request[pos++] = SOCKS5_ATYP_DOMAIN;
        request[pos++] = strlen(target_host);
        memcpy(request + pos, target_host, strlen(target_host));
        pos += strlen(target_host);
    }
    
    uint16_t port_be = htons(target_port);
    memcpy(request + pos, &port_be, PORT_SIZE);
    pos += PORT_SIZE;
    

    
    if (send(client->socket_fd, request, pos, 0) != pos) {
        perror("Error sending connect request");
        return -1;
    }
    
    ssize_t received = recv(client->socket_fd, response, sizeof(response), 0);
    if (received < SOCKS5_MIN_CONNECT_RESPONSE_SIZE) {
        perror("Error receiving connect response");
        return -1;
    }
    
    if (response[0] != SOCKS5_VERSION) {
        printf("Invalid SOCKS version in connect response: 0x%02x\n", response[0]);
        return -1;
    }
    
    if (response[1] != SOCKS5_SUCCESS) {
        printf("Connection failed, error code: 0x%02x\n", response[1]);
        return -1;
    }
    
    printf("Successfully connected to %s:%d through SOCKS5 proxy\n", target_host, target_port);
    return 0;
}

int socks5_http_test(socks5_client_t *client, const char *target_host, int target_port, const char *path) {
    if (socks5_connect_target(client, target_host, target_port) < 0) {
        return -1;
    }
    
    char http_request[HTTP_REQUEST_BUFFER_SIZE];
    snprintf(http_request, sizeof(http_request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n" 
             "\r\n", 
             path, target_host);
    
    if (send(client->socket_fd, http_request, strlen(http_request), 0) < 0) {
        perror("Error sending HTTP request");
        return -1;
    }
    
    printf("Sent HTTP request:\n%s\n", http_request);
    printf("Response:\n");
    printf("===========================================\n");
    
    char buffer[HTTP_RESPONSE_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = recv(client->socket_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }
    
    printf("\n===========================================\n");
    return 0;
}


void socks5_disconnect(socks5_client_t *client) {
    
    if (client->socket_fd >= 0) {
        
        close(client->socket_fd);
        
        client->socket_fd = -1;
    }
    
}

void interactive_menu(socks5_client_t *client) {
    char input[INPUT_BUFFER_SIZE];
    char target_host[TARGET_HOST_BUFFER_SIZE];
    char path[PATH_BUFFER_SIZE];
    int target_port;

    while (!interrupted) {
        printf("\n=== SOCKS5 Client ===\n");

        if (client->authenticated) {
            printf("Status: Authenticated as %s\n", client->username);
            printf("1. Deauthenticate (log out)\n");
            printf("2. Test HTTP connection (basic test)\n");
            printf("3. Custom HTTP request\n");
            printf("4. Disconnect and Exit\n");
        } else {
            printf("Status: Not authenticated\n");
            printf("1. Authenticate\n");
            printf("2. Test HTTP connection (basic test)\n");
            printf("3. Custom HTTP request\n");
            printf("4. Disconnect and Exit\n");
        }

        printf("Choice: ");
        if (!fgets(input, sizeof(input), stdin)) {
            if (interrupted) {
                printf("\nSignal received, exiting gracefully...\n");
            }
            break;
        }

        int choice = atoi(input);
        bool is_authenticated = client->authenticated;

        switch (choice) {
            case MENU_AUTHENTICATE:
                if (is_authenticated) {
                    client->authenticated = 0;
                    memset(client->username, 0, sizeof(client->username));
                    memset(client->password, 0, sizeof(client->password));
                    printf("Logged out. Now not authenticated.\n");
                } else {
                    printf("Username: ");
                    if (fgets(client->username, sizeof(client->username), stdin)) {
                        client->username[strcspn(client->username, "\n")] = 0;
                    }
                    printf("Password: ");
                    if (fgets(client->password, sizeof(client->password), stdin)) {
                        client->password[strcspn(client->password, "\n")] = 0;
                    }
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 1); // Ofrecer autenticación
                        if (method == USERPASS) {
                            client->authenticated = 1;
                            printf("Authentication successful!\n");
                        } else {
                            printf("Authentication failed or not required!\n");
                            client->authenticated = 0;
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                    }
                    socks5_disconnect(client);
                }
                break;

            case MENU_BASIC_TEST:
                if (socks5_connect_proxy(client) == 0) {
                    int method = socks5_negotiate(client, is_authenticated);
                    if ((is_authenticated && method == USERPASS) || (!is_authenticated && method == NOAUTH)) {
                        socks5_http_test(client, "httpbin.org", DEFAULT_HTTP_PORT, "/ip");
                    } else {
                        printf("Failed to negotiate with the required auth method.\n");
                    }
                } else {
                    printf("Failed to connect to proxy.\n");
                }
                socks5_disconnect(client);
                break;

            case MENU_CUSTOM_REQUEST:
                printf("Target host: ");
                if (fgets(target_host, sizeof(target_host), stdin)) {
                    target_host[strcspn(target_host, "\n")] = 0;
                }
                printf("Target port [80]: ");
                if (fgets(input, sizeof(input), stdin)) {
                    target_port = atoi(input);
                    if (target_port == 0) target_port = DEFAULT_HTTP_PORT;
                }
                printf("Path [/]: ");
                if (fgets(path, sizeof(path), stdin)) {
                    path[strcspn(path, "\n")] = 0;
                    if (strlen(path) == 0) strcpy(path, "/");
                }
                if (socks5_connect_proxy(client) == 0) {
                    int method = socks5_negotiate(client, is_authenticated);
                    if ((is_authenticated && method == USERPASS) || (!is_authenticated && method == NOAUTH)) {
                        socks5_http_test(client, target_host, target_port, path);
                    } else {
                        printf("Failed to negotiate with the required auth method.\n");
                    }
                } else {
                    printf("Failed to connect to proxy.\n");
                }
                socks5_disconnect(client);
                break;

            case MENU_EXIT:
                printf("Exiting...\n");
                interrupted = 1;
                break;

            default:
                printf("Invalid choice\n");
                break;
        }

        if (choice == MENU_EXIT) {
            break;
        }
    }
}

int main(int argc, char *argv[]) {


    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    socks5_client_t client = {0};



//    strcpy(client.proxy_host, DEFAULT_SOCKS5_HOST);
//    client.proxy_port = DEFAULT_SOCKS5_PORT;

    prompt_server_config(client.proxy_host, sizeof(client.proxy_host),  &client.proxy_port, false);

    client.socket_fd = -1;
    client.authenticated = 0;
    

    
    printf("SOCKS5 Client\n");
    printf("Proxy: %s:%d\n", client.proxy_host, client.proxy_port);
    printf("\nWelcome!\n");
    printf("You can connect to a SOCKS5 proxy server and perform HTTP requests through it.\n");
    printf("You can also authenticate with a username and password.\n");
    printf("Press Ctrl+C to exit at any time.\n");
    
    
    interactive_menu(&client);
    
   
    socks5_disconnect(&client);
   
    
    if (interrupted) {
        printf("[CLIENT_DEBUG] main: Received interrupt signal, exiting...\n");
    }
    
    return 0;
}