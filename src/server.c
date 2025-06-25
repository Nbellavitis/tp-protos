#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "selector.h"
#include "./Utils/tcpUtils.h"
#include <signal.h>

#define PORT "8888"
#define MAX_CLIENTS 30
#define TRUE 1

static fd_selector selector;

struct client_data {
    int fd;
    struct sockaddr_storage addr;
};

/**
 * Handler para lectura de los clientes
 */
static void handle_client_read(struct selector_key *key) {
    char buffer[1024];
    struct client_data *data = (struct client_data*) key->data;

    ssize_t bytes = recv(key->fd, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        if (bytes < 0) {
        }
        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
        free(data);
    } else {
        send(key->fd, buffer, bytes, 0);
    }
}

/**
 * Handler para cierre de los clientes
 */
static void handle_client_close(struct selector_key *key) {
    struct client_data *data = (struct client_data*) key->data;
    if (data != NULL) {
        free(data);
    }
}

/**
 * Handler para nuevas conexiones entrantes
 */
static void handle_server_read(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    int client_fd = accept(key->fd, (struct sockaddr*) &client_addr, &addrlen);
    if (client_fd < 0) {
        return;
    }

    selector_fd_set_nio(client_fd);

    struct client_data *data = malloc(sizeof(struct client_data));
    if (data == NULL) {
        close(client_fd);
        return;
    }
    data->fd = client_fd;
    memcpy(&data->addr, &client_addr, sizeof(client_addr));

    fd_handler client_handler = {
            .handle_read = handle_client_read,
            .handle_close = handle_client_close,
    };

    if (selector_register(selector, client_fd, &client_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        close(client_fd);
        free(data);
    } else {
        char addr_buf[128];
    }
}

int main(void) {
    struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = { .tv_sec = 5, .tv_nsec = 0 }
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        return EXIT_FAILURE;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        return EXIT_FAILURE;
    }

    int server_fd = setupTCPServerSocket(PORT);
    if (server_fd < 0) {
        return EXIT_FAILURE;
    }

    selector_fd_set_nio(server_fd);

    fd_handler server_handler = {
            .handle_read = handle_server_read,
    };

    if (selector_register(selector, server_fd, &server_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        return EXIT_FAILURE;
    }


    while (TRUE) {
        selector_select(selector);
    }

    selector_destroy(selector);
    selector_close();
    close(server_fd);

    return 0;
}
