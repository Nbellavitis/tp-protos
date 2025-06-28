#define _GNU_SOURCE
#include "args.h"
#include "selector.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include "sock5.h"
#include "ManagementProtocol/management.h"
#define MAXPENDING 10 //todo ME PINTO 10

// Variables globales para usuarios autorizados
static struct users* authorized_users = NULL;
static int num_authorized_users = 0;

// Funciones para acceder a los usuarios autorizados
struct users* get_authorized_users(void) {
    return authorized_users;
}

int get_num_authorized_users(void) {
    return num_authorized_users;
}

// Agregar un nuevo usuario
bool add_user(const char* username, const char* password) {
    if (username == NULL || password == NULL) {
        return false;
    }
    
    if (num_authorized_users >= MAX_USERS) {
        return false; // Array lleno
    }
    
    // Verificar que el usuario no exista ya
    for (int i = 0; i < num_authorized_users; i++) {
        if (authorized_users[i].name != NULL && strcmp(authorized_users[i].name, username) == 0) {
            return false; // Usuario ya existe
        }
    }
    
    // Crear copias de los strings (necesario porque el payload es temporal)
    char* name_copy = malloc(strlen(username) + 1);
    char* pass_copy = malloc(strlen(password) + 1);
    
    if (name_copy == NULL || pass_copy == NULL) {
        free(name_copy);
        free(pass_copy);
        return false;
    }
    
    strcpy(name_copy, username);
    strcpy(pass_copy, password);
    
    authorized_users[num_authorized_users].name = name_copy;
    authorized_users[num_authorized_users].pass = pass_copy;
    num_authorized_users++;
    
    printf("Usuario agregado: %s\n", username);
    return true;
}

// Eliminar un usuario
bool delete_user(const char* username) {
    if (username == NULL) {
        return false;
    }
    
    for (int i = 0; i < num_authorized_users; i++) {
        if (authorized_users[i].name != NULL && strcmp(authorized_users[i].name, username) == 0) {
            // Liberar memoria de los strings
            free(authorized_users[i].name);
            free(authorized_users[i].pass);
            
            // Mover todos los elementos posteriores una posición hacia atrás
            for (int j = i; j < num_authorized_users - 1; j++) {
                authorized_users[j] = authorized_users[j + 1];
            }
            
            // Limpiar el último elemento
            authorized_users[num_authorized_users - 1].name = NULL;
            authorized_users[num_authorized_users - 1].pass = NULL;
            
            num_authorized_users--;
            printf("Usuario eliminado: %s\n", username);
            return true;
        }
    }
    
    return false; // Usuario no encontrado
}

static int setupSockAddr(char *addr, unsigned short port,void * result,socklen_t * lenResult) {
    int ipv6 = strchr(addr, ':') != NULL;
    if(ipv6){
        struct sockaddr_in6 sockipv6;
        memset(&sockipv6, 0, sizeof(sockipv6));
        sockipv6.sin6_family = AF_INET6;
        sockipv6.sin6_port = htons(port);
        if(inet_pton(AF_INET6, addr, &sockipv6.sin6_addr) <= 0) {
            fprintf(stderr, "Invalid IPv6 address: %s\n", addr);
            return -1;
        }
       *(struct sockaddr_in6 *) result = sockipv6;
        *lenResult = sizeof(struct sockaddr_in6);
        return 0;
    }
    //ACA ES IPV4
    struct sockaddr_in sockipv4;
    memset(&sockipv4, 0, sizeof(sockipv4));
    sockipv4.sin_family = AF_INET;
    sockipv4.sin_port = htons(port);
    if(inet_pton(AF_INET, addr, &sockipv4.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", addr);
        return -1;
    }
    *(struct sockaddr_in *) result = sockipv4;
    *lenResult = sizeof(struct sockaddr_in);
    return 0;
}


int main (int argc,char * argv[]){
    printf("Starting SOCKS5 Proxy Server\n");
    //
    // // Ignorar SIGPIPE para evitar que el servidor se crashee
    // signal(SIGPIPE, SIG_IGN);
    //
    selector_status ss= SELECTOR_SUCCESS;
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }

    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        fprintf(stdout, "Failed to initialize selector\n");
        exit(1);
    }
   struct fdselector * selector = selector_new(FD_SETSIZE);
    if (selector == NULL) {
        fprintf(stdout, "Failed to create selector\n");
        exit(1);
    }
    struct socks5args args;
    parse_args(argc, argv, &args);
    
    // Inicializar usuarios autorizados - copiar a memoria dinámica
    authorized_users = calloc(MAX_USERS, sizeof(struct users));
    for (int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        // Copiar strings a memoria dinámica
        authorized_users[i].name = malloc(strlen(args.users[i].name) + 1);
        authorized_users[i].pass = malloc(strlen(args.users[i].pass) + 1);
        strcpy(authorized_users[i].name, args.users[i].name);
        strcpy(authorized_users[i].pass, args.users[i].pass);
        num_authorized_users++;
    }
    struct sockaddr_storage auxAddr;
    memset(&auxAddr, 0, sizeof(auxAddr));
    socklen_t auxAddrLen = sizeof(auxAddr);
    int server = -1;
    if (setupSockAddr(args.socks_addr, args.socks_port, &auxAddr, &auxAddrLen) < 0) {
        fprintf(stdout, "Failed to setup SOCKS address\n");
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }
    server = socket(auxAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        fprintf(stdout, "Failed to create server socket: %s\n", strerror(errno));
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }
    int enable = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (bind(server, (struct sockaddr *)&auxAddr, auxAddrLen) < 0) {
        fprintf(stdout, "Failed to bind server socket: %s\n", strerror(errno));
        close(server);
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }
    if (listen(server, MAXPENDING) < 0) {
        fprintf(stdout, "Failed to listen on server socket: %s\n", strerror(errno));
        close(server);
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }
    if (selector_fd_set_nio(server) == -1) {
        fprintf(stdout, "Failed to set server socket to non-blocking: %s\n", strerror(errno));
        close(server);
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }

    const fd_handler socksv5 = {
        .handle_read = socksv5PassiveAccept
    };
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stdout, "Failed to register server socket with selector: %s\n", selector_error(ss));
        selector_close();
        exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
    }
    printf("SOCKS5 Proxy Server listening on %s:%d\n", args.socks_addr, args.socks_port);
    
    // Configurar socket de management
    struct sockaddr_storage mgmtAddr;
    memset(&mgmtAddr, 0, sizeof(mgmtAddr));
    socklen_t mgmtAddrLen = sizeof(mgmtAddr);
    int mgmt_server = -1;
    
    if (setupSockAddr(args.mng_addr, args.mng_port, &mgmtAddr, &mgmtAddrLen) < 0) {
        fprintf(stdout, "Failed to setup Management address\n");
        exit(1);
    }
    
    mgmt_server = socket(mgmtAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (mgmt_server < 0) {
        fprintf(stdout, "Failed to create management socket: %s\n", strerror(errno));
        exit(1);
    }
    
    setsockopt(mgmt_server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (bind(mgmt_server, (struct sockaddr *)&mgmtAddr, mgmtAddrLen) < 0) {
        fprintf(stdout, "Failed to bind management socket: %s\n", strerror(errno));
        close(mgmt_server);
        exit(1);
    }
    
    if (listen(mgmt_server, MAXPENDING) < 0) {
        fprintf(stdout, "Failed to listen on management socket: %s\n", strerror(errno));
        close(mgmt_server);
        exit(1);
    }
    
    if (selector_fd_set_nio(mgmt_server) == -1) {
        fprintf(stdout, "Failed to set management socket to non-blocking: %s\n", strerror(errno));
        close(mgmt_server);
        exit(1);
    }
    
    const fd_handler management = {
        .handle_read = management_passive_accept
    };
    ss = selector_register(selector, mgmt_server, &management, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stdout, "Failed to register management socket with selector: %s\n", selector_error(ss));
        selector_close();
        exit(1);
    }
    
    printf("Management Server listening on %s:%d\n", args.mng_addr, args.mng_port);
    
    while(true){
        printf("[DEBUG] MAIN: Antes de selector_select\n");
        ss = selector_select(selector);
        printf("[DEBUG] MAIN: Después de selector_select\n");
        if (ss != SELECTOR_SUCCESS) {
            fprintf(stdout, "Selector error: %s\n", selector_error(ss));
            selector_close();
            exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
        }
        stats_print();
    }
}