#include "client_utils.h"
#include <errno.h>

char * mgmnt_server_ip = "Management server IP [" DEFAULT_MGMT_HOST "]: ";
char * socks_server_ip = "Management server IP [" DEFAULT_SOCKS5_HOST "]: ";

char * mgmnt_server_port = "Management server IP [" DEFAULT_MGMT_HOST "]: ";
char * socks_server_port = "Management server IP [" DEFAULT_SOCKS5_HOST "]: ";


#define BUFF_SIZE 256



int read_line(const char *prompt, char *buf, size_t n)
{
    printf("%s", prompt);
    if (!fgets(buf, (int)n, stdin))
    {
        clearerr(stdin);
        puts("\n");
        return -1;
    }
    buf[strcspn(buf, "\n")] = 0;
    return 0;
}

int ask_choice(const char *prompt, int min, int max)
{
    char line[INPUT_SMALL_BUF];
    int  v;
    for(;;)
    {
        if(read_line(prompt, line, sizeof line) < 0) {
            return -1;
        };
        v = atoi(line);
        if (v >= min && v <= max) return v;
        printf("Value %d‑%d\n", min, max);
    }
    return -1;
}

void prompt_server_config(char *host, size_t host_sz, int *port, bool mgmt)
{
    char * str = mgmt ? mgmnt_server_ip:socks_server_ip;
    char buf[BUFF_SIZE];

    for (;;) {
        if (read_line(str,
                buf, sizeof buf) < 0 ||
                                   buf[0] == '\0')
        {
            // EOF or blank ⇒ use default
            strncpy(host, DEFAULT_MGMT_HOST, host_sz);
            break;
        }
        struct in_addr  tmp4;
        struct in6_addr tmp6;
        if (inet_pton(AF_INET,  buf, &tmp4) == 1 ||
            inet_pton(AF_INET6, buf, &tmp6) == 1)
        {
            strncpy(host, buf, host_sz);
            break;
        }
        puts("IP inválida. Debe ser IPv4 o IPv6.");
    }

    // --- port loop ---
    for (;;) {
        char prompt[INPUT_SMALL_BUF];

        if(mgmt){
            snprintf(prompt, sizeof prompt,
                     "Management server port [%d]: ", DEFAULT_MGMT_PORT);
        }else{
            snprintf(prompt, sizeof prompt,"Socks5 server port [%d]: ", DEFAULT_SOCKS5_PORT);
        }


        if (read_line(prompt, buf, sizeof buf) < 0 ||
            buf[0] == '\0')
        {
            *port = DEFAULT_MGMT_PORT;
            break;
        }
        errno = 0;
        char *end;
        long v = strtol(buf, &end, 10);
        if (errno == 0 && *end == '\0'
            && v >= 1 && v <= MAX_PORT_NUMBER)
        {
            *port = (int)v;
            break;
        }
        fprintf(stderr,
                "Puerto inválido. Entre 1 y %d.\n",
                MAX_PORT_NUMBER);
    }
}