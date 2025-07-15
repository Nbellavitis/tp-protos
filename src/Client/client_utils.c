#include "client_utils.h"
#include <errno.h>
#include <signal.h>
#include <netdb.h>

// Global configuration strings
char *mgmnt_server_ip = "Management server IP [" DEFAULT_MGMT_HOST "]: ";
char *socks_server_ip = "Socks5 server IP [" DEFAULT_SOCKS5_HOST "]: ";

// Buffer size constants
#define BUFF_SIZE 256
#define INPUT_SMALL_BUF 32


int read_line(const char *prompt, char *buf, size_t n) {
    printf("%s", prompt);
    if (!fgets(buf, (int)n, stdin)) {
        clearerr(stdin);
        puts("\n");
        return -1;
    }
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

int ask_choice(const char *prompt, int min, int max) {
    char line[INPUT_SMALL_BUF];
    int v;
    for(;;) {
        if (read_line(prompt, line, sizeof line) < 0) {
            return -1;
        }
        v = atoi(line);
        if (v >= min && v <= max) return v;
        printf("Value %d-%d\n", min, max);
    }
}

int connect_server(const char *server_host, int server_port, int *socket_fd) {
    char portstr[6];
    snprintf(portstr, sizeof portstr, "%d", server_port);

    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_NUMERICSERV
    }, *res, *rp;

    int err = getaddrinfo(server_host, portstr, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "DNS resolution failed for '%s:%d': %s\n",
                server_host, server_port, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            perror("socket creation failed");
            continue;
        }

        // Set connection timeout (5 seconds)
        struct timeval timeout = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // Success
        }

        // Detailed error reporting
        char addr_str[INET6_ADDRSTRLEN];
        const char *result = NULL;
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
            result = inet_ntop(AF_INET, &ipv4->sin_addr, addr_str, sizeof(addr_str));
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
            result = inet_ntop(AF_INET6, &ipv6->sin6_addr, addr_str, sizeof(addr_str));
        }

        if (result != NULL) {
            fprintf(stderr, "Connection attempt to %s:%d failed: %s\n",
                    addr_str, server_port, strerror(errno));
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd == -1) {
        fprintf(stderr, "Could not establish connection to %s:%d\n",
                server_host, server_port);
        return -1;
    }

    // Disable timeout after successful connection
    struct timeval timeout = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    *socket_fd = fd;
    printf("Successfully connected to %s:%d\n", server_host, server_port);
    return 0;
}

void prompt_server_config(char *host, size_t host_sz, int *port, bool mgmt) {
    char *str = mgmt ? mgmnt_server_ip : socks_server_ip;
    char buf[BUFF_SIZE];

    // Host/IP configuration
    for (;;) {
        if (read_line(str, buf, sizeof buf) < 0 || buf[0] == '\0') {
            strncpy(host, mgmt ? DEFAULT_MGMT_HOST : DEFAULT_SOCKS5_HOST, host_sz);
            break;
        }

        struct in_addr tmp4;
        struct in6_addr tmp6;
        if (inet_pton(AF_INET, buf, &tmp4) == 1) {
            strncpy(host, buf, host_sz);
            break;
        } else if (inet_pton(AF_INET6, buf, &tmp6) == 1) {
            strncpy(host, buf, host_sz);
            break;
        }
        puts("Invalid IP address. Must be IPv4 or IPv6.");
    }

    // Port configuration
    for (;;) {
        char prompt[INPUT_SMALL_BUF];
        int default_port = mgmt ? DEFAULT_MGMT_PORT : DEFAULT_SOCKS5_PORT;

        snprintf(prompt, sizeof prompt, "%s server port [%d]: ",
                 mgmt ? "Management" : "Socks5", default_port);

        if (read_line(prompt, buf, sizeof buf) < 0 || buf[0] == '\0') {
            *port = default_port;
            break;
        }

        errno = 0;
        char *end;
        long v = strtol(buf, &end, 10);
        if (errno == 0 && *end == '\0' && v >= 1 && v <= MAX_PORT_NUMBER) {
            *port = (int)v;
            break;
        }
        fprintf(stderr, "Invalid port. Must be between 1 and %d.\n", MAX_PORT_NUMBER);
    }
}