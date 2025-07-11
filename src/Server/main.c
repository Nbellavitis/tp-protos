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
#include "../logger.h"
#define MAXPENDING 10 //todo ME PINTO 10

static bool killed = false;

static int endProgram(struct users * users,fd_selector selector, selector_status ss, int server, int mgmt_server,char * error);

        void sig_handler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        LOG_INFO("Received signal %d, shutting down...", signum);
        killed = true;
    }
}
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
    
    LOG_INFO("User added: %s", username);
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
            LOG_INFO("User deleted: %s", username);
            return true;
        }
    }
    
    return false; // Usuario no encontrado
}

// Cambiar la contraseña de un usuario
bool change_user_password(const char* username, const char* new_password) {
    if (username == NULL || new_password == NULL) {
        return false;
    }
    for (int i = 0; i < num_authorized_users; i++) {
        if (authorized_users[i].name != NULL && strcmp(authorized_users[i].name, username) == 0) {
            // Cambiar la contraseña
            free(authorized_users[i].pass);
            char* pass_copy = malloc(strlen(new_password) + 1);
            if (pass_copy == NULL) {
                return false;
            }
            strcpy(pass_copy, new_password);
            authorized_users[i].pass = pass_copy;
            LOG_INFO("Password changed for user: %s", username);
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
            LOG_ERROR("Invalid IPv6 address: %s", addr);
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
        LOG_ERROR("Invalid IPv4 address: %s", addr);
        return -1;
    }
    *(struct sockaddr_in *) result = sockipv4;
    *lenResult = sizeof(struct sockaddr_in);
    return 0;
}


int main (int argc,char * argv[]){
    LOG_INFO("Starting SOCKS5 Proxy Server");
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    selector_status ss= SELECTOR_SUCCESS;
    char * error = NULL;
    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }

    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        error = "Failed to initialize selector";
        return endProgram(authorized_users, NULL, ss, -1, -1,error);
    }
   struct fdselector * selector = selector_new(FD_SETSIZE);
    if (selector == NULL) {
        error = "Failed to create selector";
        return endProgram(authorized_users, selector, ss, -1, -1,error);
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
        error = "Invalid address or port for SOCKS5 server";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }
    server = socket(auxAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) {
        error = "Failed to create socket for SOCKS5 server";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }
    int enable = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (bind(server, (struct sockaddr *)&auxAddr, auxAddrLen) < 0) {
        error = "Failed to bind socket for SOCKS5 server";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }
    if (listen(server, MAXPENDING) < 0) {
        error = "Failed to listen on socket for SOCKS5 server";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }
    if (selector_fd_set_nio(server) == -1) {
        error = "Failed to set non-blocking mode for SOCKS5 server socket";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }

    const fd_handler socksv5 = {
        .handle_read = socksv5PassiveAccept
    };
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        error = "Failed to register SOCKS5 server socket with selector";
        return endProgram(authorized_users, selector, ss, server, -1,error);
    }
    LOG_INFO("SOCKS5 Proxy Server listening on %s:%d", args.socks_addr, args.socks_port);
    
    // Configurar socket de management

    struct sockaddr_storage mgmtAddr;
    memset(&mgmtAddr, 0, sizeof(mgmtAddr));
    socklen_t mgmtAddrLen = sizeof(mgmtAddr);
    int mgmt_server = -1;
    
    if (setupSockAddr(args.mng_addr, args.mng_port, &mgmtAddr, &mgmtAddrLen) < 0) {
        error = "Invalid address or port for Management server";
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    
    mgmt_server = socket(mgmtAddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (mgmt_server < 0) {
        error = "Failed to create socket for Management server";
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    
    setsockopt(mgmt_server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (bind(mgmt_server, (struct sockaddr *)&mgmtAddr, mgmtAddrLen) < 0) {
        error = "Failed to bind socket for Management server";
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    
    if (listen(mgmt_server, MAXPENDING) < 0) {
        error = "Failed to listen on socket for Management server";
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    
    if (selector_fd_set_nio(mgmt_server) == -1) {
        error = "Failed to set non-blocking mode for Management server socket";
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    
    const fd_handler management = {
        .handle_read = management_passive_accept
    };
    ss = selector_register(selector, mgmt_server, &management, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
    }
    mgtm_init_admin();
    LOG_INFO("Management Server listening on %s:%d", args.mng_addr, args.mng_port);
    
    while(!killed){
        LOG_DEBUG("Main event loop: Before selector_select");
        ss = selector_select(selector);
        LOG_DEBUG("Main event loop: After selector_select");
        if (ss != SELECTOR_SUCCESS) {
            return endProgram(authorized_users, selector, ss, server, mgmt_server,error);
        }
        // stats_print();
    }
    return endProgram(authorized_users, selector, ss, server, mgmt_server,NULL);
}
int endProgram(struct users * users,fd_selector selector, selector_status ss, int server, int mgmt_server,char * error) {
    int ret= 0;
    if (users != NULL) {
        for (int i = 0; i < num_authorized_users; i++) {
            if (users[i].name != NULL) {
                free(users[i].name);  // Liberar username
            }
            if (users[i].pass != NULL) {
                free(users[i].pass);  // Liberar password
            }
        }
       free(users);
    }
    if (ss != SELECTOR_SUCCESS) {
        LOG_ERROR("Selector error: %s", selector_error(ss));
        ret = -1; // Indicar error en el selector
    }else if (errno < 0) {
        LOG_ERROR("System error: %s", strerror(errno));
        ret = -1; // Indicar error de sistema
    } else if (error != NULL) {
        LOG_ERROR("Application error: %s", error);
        ret = -1; // Indicar error específico
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    if (server >= 0) {
        close(server);
    }

    if (mgmt_server >= 0) {
        close(mgmt_server);
    }

    return ret;

}