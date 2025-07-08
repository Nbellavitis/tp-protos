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
#include "../Server/args.h"

// Variable global para detectar Ctrl+C
volatile sig_atomic_t interrupted = 0;

void signal_handler(int sig) {
  
    interrupted = 1;
}

/*
 * @TODO hay que arreglar cuando haces curl a goolge.com en el puerto 81. 
 */


// SOCKS5 Protocol Constants
#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_VERSION 0x01
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03

#define AUTH_METHOD_NONE 0x00
#define AUTH_METHOD_USERPASS 0x02
#define AUTH_METHOD_FAIL 0xFF

typedef struct {
    int socket_fd;
    char proxy_host[256];
    int proxy_port;
    char username[256];
    char password[256];
    int authenticated;
} socks5_client_t;

// Function declarations
int socks5_authenticate(socks5_client_t *client);

// Conectar al proxy SOCKS5
int socks5_connect_proxy(socks5_client_t *client) {
 
    
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        perror("Error creating socket");
        return -1;
    }
    
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(client->proxy_port);
    
    if (inet_pton(AF_INET, client->proxy_host, &proxy_addr.sin_addr) <= 0) {
        perror("Invalid proxy address");
        close(client->socket_fd);
        return -1;
    }
    
    if (connect(client->socket_fd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Error connecting to proxy");
        close(client->socket_fd);
        return -1;
    }
    
    return 0;
}

// Negociación inicial SOCKS5
// Devuelve el método elegido (0x00, 0x02, 0xFF) o -1 en error
int socks5_negotiate(socks5_client_t *client, int offer_auth) {
    uint8_t request[4];
    uint8_t response[2];

    request[0] = SOCKS5_VERSION;    // Version
    if (offer_auth) {
        request[1] = 1;                 // Number of methods
        request[2] = AUTH_METHOD_USERPASS; // Username/password
    } else {
        request[1] = 1;                 // Number of methods
        request[2] = AUTH_METHOD_NONE;  // No authentication
    }

    int req_len = 3;

    if (send(client->socket_fd, request, req_len, 0) != req_len) {
        perror("[SOCKS5] Error sending negotiation request");
        return -1;
    }

    // Recibir respuesta del servidor
    ssize_t received = recv(client->socket_fd, response, 2, 0);
    if (received != 2) {
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

    if (selected_method == AUTH_METHOD_USERPASS) {
        int auth_result = socks5_authenticate(client);
        if (auth_result == 0) {
            return AUTH_METHOD_USERPASS;
        } else {
            return -1;
        }
    } else if (selected_method == AUTH_METHOD_NONE) {
        return AUTH_METHOD_NONE;
    } else {
        printf("[SOCKS5] Server selected unknown authentication method: 0x%02x\n", selected_method);
        return -1;
    }
}

// Autenticación username/password
int socks5_authenticate(socks5_client_t *client) {
    uint8_t request[512];
    uint8_t response[2];
    int pos = 0;
    
   
    
    // Construir request de autenticación
    request[pos++] = SOCKS5_AUTH_VERSION;           // Version
    request[pos++] = strlen(client->username);      // Username length
    memcpy(request + pos, client->username, strlen(client->username));
    pos += strlen(client->username);
    request[pos++] = strlen(client->password);      // Password length
    memcpy(request + pos, client->password, strlen(client->password));
    pos += strlen(client->password);
    
   
    
    if (send(client->socket_fd, request, pos, 0) != pos) {
        perror("[SOCKS5] Error sending authentication");
        return -1;
    }
    
    // Recibir respuesta
  
    ssize_t received = recv(client->socket_fd, response, 2, 0);
    if (received != 2) {
        printf("[SOCKS5] Error receiving authentication response, got %ld bytes\n", received);
        return -1;
    }
    
    
    
    if (response[0] != SOCKS5_AUTH_VERSION) {
        printf("[SOCKS5] Invalid auth version in response: 0x%02x\n", response[0]);
        return -1;
    }
    
    if (response[1] != 0x00) {
        printf("[SOCKS5] Authentication failed. Status: 0x%02x\n", response[1]);
        return -1;
    }
    
    
    return 0;
}

// Conectar a través del proxy SOCKS5
int socks5_connect_target(socks5_client_t *client, const char *target_host, int target_port) {
    uint8_t request[512];
    uint8_t response[512];
    int pos = 0;
    
    // Construir request de conexión

    request[pos++] = SOCKS5_VERSION;        // Version
    request[pos++] = SOCKS5_CMD_CONNECT;    // Command: CONNECT
    request[pos++] = 0x00;                  // Reserved
    
    // Determinar tipo de dirección
    struct in_addr addr;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, target_host, &addr) == 1) {
        // Es una dirección IPv4
        request[pos++] = SOCKS5_ATYP_IPV4;
        memcpy(request + pos, &addr, 4);
        pos += 4;
    } else if (inet_pton(AF_INET6, target_host, &addr6) == 1) {
        // Es una dirección IPv6
        request[pos++] = 0x04; // SOCKS5_ATYP_IPV6
        memcpy(request + pos, &addr6, 16);
        pos += 16;
    } else {
        // Es un nombre de dominio
        request[pos++] = SOCKS5_ATYP_DOMAIN;
        request[pos++] = strlen(target_host);
        memcpy(request + pos, target_host, strlen(target_host));
        pos += strlen(target_host);
    }
    
    // Puerto (big-endian)
    uint16_t port_be = htons(target_port);
    memcpy(request + pos, &port_be, 2);
    pos += 2;
    

    
    if (send(client->socket_fd, request, pos, 0) != pos) {
        perror("Error sending connect request");
        return -1;
    }
    
    // Recibir respuesta
    ssize_t received = recv(client->socket_fd, response, sizeof(response), 0);
    if (received < 4) {
        perror("Error receiving connect response");
        return -1;
    }
    
    if (response[0] != SOCKS5_VERSION) {
        printf("Invalid SOCKS version in connect response: 0x%02x\n", response[0]);
        return -1;
    }
    
    if (response[1] != 0x00) {
        printf("Connection failed, error code: 0x%02x\n", response[1]);
        return -1;
    }
    
    printf("Successfully connected to %s:%d through SOCKS5 proxy\n", target_host, target_port);
    return 0;
}

// Realizar petición HTTP simple
int socks5_http_test(socks5_client_t *client, const char *target_host, int target_port, const char *path) {
    if (socks5_connect_target(client, target_host, target_port) < 0) {
        return -1;
    }
    
    // Construir petición HTTP
    char http_request[1024];
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
    
    // Leer respuesta
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = recv(client->socket_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }
    
    printf("\n===========================================\n");
    return 0;
}

// Desconectar
void socks5_disconnect(socks5_client_t *client) {
    
    if (client->socket_fd >= 0) {
        
        close(client->socket_fd);
        
        client->socket_fd = -1;
    } else {
        
    }
    
}

// Menú interactivo
void interactive_menu(socks5_client_t *client) {
    char input[512];
    char target_host[256];
    char path[512];
    int target_port;
    
    while (1) {
        printf("\n=== SOCKS5 Client ===\n");
        if (!client->authenticated) {
            printf("Status: Not authenticated\n");
            printf("1. Authenticate\n");
            printf("2. Test HTTP connection (basic test)\n");
            printf("3. Custom HTTP request\n");
            printf("4. Disconnect and Exit\n");
            printf("Choice: ");
            if (!fgets(input, sizeof(input), stdin)) {
                break;
            }
            int choice = atoi(input);
            switch (choice) {
                case 1:
                    printf("Username: ");
                    if (fgets(client->username, sizeof(client->username), stdin)) {
                        client->username[strcspn(client->username, "\n")] = 0;
                    }
                    printf("Password: ");
                    if (fgets(client->password, sizeof(client->password), stdin)) {
                        client->password[strcspn(client->password, "\n")] = 0;
                    }
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 1); // SOLO autenticación
                        if (method == AUTH_METHOD_USERPASS) {
                            client->authenticated = 1;
                            printf("Authentication successful!\n");
                        } else if (method == AUTH_METHOD_NONE) {
                            client->authenticated = 0;
                            printf("No authentication required by server.\n");
                        } else {
                            printf("Authentication failed!\n");
                            client->authenticated = 0;
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                        client->authenticated = 0;
                    }
                    socks5_disconnect(client);
                    break;
                case 2:
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 0); // SOLO sin autenticación
                        if (method == AUTH_METHOD_NONE) {
                            socks5_http_test(client, "httpbin.org", 80, "/ip");
                        } else {
                            printf("Failed to connect or negotiate\n");
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                    }
                    socks5_disconnect(client);
                    break;
                case 3:
                    printf("Target host: ");
                    if (fgets(target_host, sizeof(target_host), stdin)) {
                        target_host[strcspn(target_host, "\n")] = 0;
                    }
                    printf("Target port [80]: ");
                    if (fgets(input, sizeof(input), stdin)) {
                        target_port = atoi(input);
                        if (target_port == 0) target_port = 80;
                    }
                    printf("Path [/]: ");
                    if (fgets(path, sizeof(path), stdin)) {
                        path[strcspn(path, "\n")] = 0;
                        if (strlen(path) == 0) strcpy(path, "/");
                    }
                    printf("\n[INFO] Intentando conectar a %s:%d a través del proxy...\n", target_host, target_port);
                    printf("[INFO] Si el destino no responde, la conexión puede demorar varios segundos (timeout de red). La aplicación NO está colgada.\n");
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 0); // SOLO sin autenticación
                        if (method == AUTH_METHOD_NONE) {
                            socks5_http_test(client, target_host, target_port, path);
                        } else {
                            printf("Failed to connect or negotiate\n");
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                    }
                    socks5_disconnect(client);
                    break;
                case 4:
                    printf("Exiting...\n");
                    return;
                default:
                    printf("Invalid choice\n");
                    break;
            }
        } else {
            printf("Status: Authenticated as %s\n", client->username);
            printf("1. Deauthenticate (log out)\n");
            printf("2. Test HTTP connection (basic test)\n");
            printf("3. Custom HTTP request\n");
            printf("4. Disconnect and Exit\n");
            printf("Choice: ");
            if (!fgets(input, sizeof(input), stdin)) {
                break;
            }
            int choice = atoi(input);
            switch (choice) {
                case 1:
                    client->authenticated = 0;
                    memset(client->username, 0, sizeof(client->username));
                    memset(client->password, 0, sizeof(client->password));
                    printf("Logged out. Now not authenticated.\n");
                    break;
                case 2:
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 1); // autenticado
                        if (method == AUTH_METHOD_USERPASS) {
                            socks5_http_test(client, "httpbin.org", 80, "/ip");
                        } else {
                            printf("Failed to connect or negotiate\n");
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                    }
                    socks5_disconnect(client);
                    break;
                case 3:
                    printf("Target host: ");
                    if (fgets(target_host, sizeof(target_host), stdin)) {
                        target_host[strcspn(target_host, "\n")] = 0;
                    }
                    printf("Target port [80]: ");
                    if (fgets(input, sizeof(input), stdin)) {
                        target_port = atoi(input);
                        if (target_port == 0) target_port = 80;
                    }
                    printf("Path [/]: ");
                    if (fgets(path, sizeof(path), stdin)) {
                        path[strcspn(path, "\n")] = 0;
                        if (strlen(path) == 0) strcpy(path, "/");
                    }
                    printf("\n[INFO] Intentando conectar a %s:%d a través del proxy...\n", target_host, target_port);
                    printf("[INFO] Si el destino no responde, la conexión puede demorar varios segundos (timeout de red). La aplicación NO está colgada.\n");
                    if (socks5_connect_proxy(client) == 0) {
                        int method = socks5_negotiate(client, 1); // autenticado
                        if (method == AUTH_METHOD_USERPASS) {
                            socks5_http_test(client, target_host, target_port, path);
                        } else {
                            printf("Failed to connect or negotiate\n");
                        }
                    } else {
                        printf("Failed to connect to proxy.\n");
                    }
                    socks5_disconnect(client);
                    break;
                case 4:
                    printf("Exiting...\n");
                    return;
                default:
                    printf("Invalid choice\n");
                    break;
            }
        }
    }
}

int main(int argc, char *argv[]) {
   
    
    // Configurar manejador de señales
    signal(SIGINT, signal_handler);
    
    socks5_client_t client = {0};
    
    // Valores por defecto
    strcpy(client.proxy_host, DEFAULT_SOCKS5_HOST);
    client.proxy_port = DEFAULT_SOCKS5_PORT;
    client.socket_fd = -1;
    client.authenticated = 0;
    
    // Parsear argumentos
    if (argc >= 2) {
        strcpy(client.proxy_host, argv[1]);
    }
    if (argc >= 3) {
        client.proxy_port = atoi(argv[2]);
    }
    if (argc >= 4) {
        strcpy(client.username, argv[3]);
    }
    if (argc >= 5) {
        strcpy(client.password, argv[4]);
    }
    
    printf("SOCKS5 Client\n");
    printf("Proxy: %s:%d\n", client.proxy_host, client.proxy_port);
    printf("\nWelcome!\n");
    printf("- Puedes autenticarte opcionalmente, o usar el proxy sin autenticación\n");
    printf("- Realiza requests HTTP a través del proxy\n");
    printf("- Usa Ctrl+C para salir en cualquier momento\n\n");
    
    
    interactive_menu(&client);
    
   
    socks5_disconnect(&client);
   
    
    if (interrupted) {
        printf("[CLIENT_DEBUG] main: El programa fue interrumpido por Ctrl+C\n");
    }
    
    return 0;
}