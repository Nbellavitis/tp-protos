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
#define MAXPENDING 10 // ME PINTO 10
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
    while(true){
        printf("[DEBUG] MAIN: Antes de selector_select\n");
        ss = selector_select(selector);
        printf("[DEBUG] MAIN: Después de selector_select\n");
        if (ss != SELECTOR_SUCCESS) {
            fprintf(stdout, "Selector error: %s\n", selector_error(ss));
            selector_close();
            exit(1);   // todo VER COMO BORRAR TODO (NO HACER EXIT)
        }
    }
}