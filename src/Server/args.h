#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include "./users.h"

#define MAX_USERS 10

// Network configuration constants
#define DEFAULT_SOCKS_PORT      1080
#define DEFAULT_MGMT_PORT       8080
#define MAX_PORT_NUMBER         65536
#define DEFAULT_MGMT_ADDR       "127.0.0.1"
#define DEFAULT_SOCKS_ADDR "0.0.0.0"


struct socks5args
{
    char* socks_addr;
    unsigned short socks_port;

    char* mng_addr;
    unsigned short mng_port;

    bool disectors_enabled;

    struct users users[MAX_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void
parse_args(const int argc, char** argv, struct socks5args* args);

#endif
