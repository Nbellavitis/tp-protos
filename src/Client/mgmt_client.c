#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../management_constants.h"
#include "client_utils.h"


#define INPUT_LINE_BUF             (MAX_USERNAME_LEN + 1)
#define CREDENTIALS_BUF            (MAX_USERNAME_LEN + 1 + MAX_PASSWORD_LEN + 1)
#define HEADER_LEN                 3                              /* VER+CMD+LEN */
#define STATS_FIELDS               5
#define STATS_PAYLOAD_BYTES        (STATS_FIELDS * sizeof(uint32_t))
#define RESPONSE_BUFFER_SIZE       MGMT_RESPONSE_SIZE
#define FULL_PAYLOAD_BUF           (MAX_MGMT_PAYLOAD_LEN + 1)     /* con '\0'*/
#define INPUT_BUF_SIZE   64
#define MAX_PORT_NUMBER 65535



static const uint32_t BUF_SIZE_OPTIONS[] =
        {
                4 * 1024,
                8 * 1024,
                16 * 1024,
                32 * 1024,
                64 * 1024,
                128 * 1024
        };

#define BUF_OPTIONS_COUNT  (sizeof BUF_SIZE_OPTIONS / sizeof BUF_SIZE_OPTIONS[0])

static uint8_t read_buffer[FULL_PAYLOAD_BUF+1];

typedef struct
{
    int  socket_fd;
    char server_host[256];
    int  server_port;
    int  authenticated;
} mgmt_client_t;



static int check_len(const char *label, const char *s, size_t max)
{
    if (strlen(s) > max)
    {
        printf("%s too long (>%zu)\n", label, max);
        return -1;
    }
    return 0;
}

static const char *status_to_str(uint8_t st)
{
    static const char *tbl[] =
            {
                    "Success",
                    "Error",
                    "Auth required",
                    "Auth failed",
                    "Not found",
                    "Capacity full",
                    "Invalid format",
                    "Length exceeded",
                    "Already exists",
                    "Not allowed",
                    "Reserved user"
            };
    return (st <= STATUS_RESERVED_USER) ? tbl[st] : "Unknown status";
}

static int send_raw(mgmt_client_t *c, uint8_t cmd, const uint8_t *pl, uint8_t len)
{
    uint8_t msg[HEADER_LEN + MAX_MGMT_PAYLOAD_LEN];
    msg[0] = MANAGEMENT_VERSION;
    msg[1] = cmd;
    msg[2] = len;
    if (len) memcpy(msg + HEADER_LEN, pl, len);
    return send(c->socket_fd, msg, HEADER_LEN + len, MSG_NOSIGNAL) ==
           HEADER_LEN + len ? 0 : -1;
}

static int recv_raw(mgmt_client_t *c, uint8_t *st, uint8_t *len)
{
    uint8_t hdr[HEADER_LEN];
    if (read(c->socket_fd, hdr, HEADER_LEN) != HEADER_LEN) return -1;
    if (hdr[0] != MANAGEMENT_VERSION) return -1;
    *st  = hdr[1];
    *len = hdr[2];
    if (*len && read(c->socket_fd, read_buffer, *len) != *len) return -1;
    return 0;
}
/* -------------------------------------------------------------------------- */
static void disconnect(mgmt_client_t *c)
{
    if (c->socket_fd >= 0) close(c->socket_fd);
    c->socket_fd = -1;
    c->authenticated = 0;
}


static int auth_server(mgmt_client_t *c)
{
    char u[INPUT_LINE_BUF];
    char p[INPUT_LINE_BUF];
    if(read_line("Username: ", u, sizeof u) < 0){
        return -1;
    };
    if(read_line("Password: ", p, sizeof p)<0){
        return -1;
    };
    if (check_len("Username", u, MAX_USERNAME_LEN) ||
        check_len("Password", p, MAX_PASSWORD_LEN)) return -1;

    char cred[CREDENTIALS_BUF];
    snprintf(cred, sizeof cred, "%s:%s", u, p);
    if (send_raw(c, CMD_AUTH, (uint8_t *)cred, (uint8_t)strlen(cred)) < 0)
    {
        perror("send()failed—could not transmit authentication message");
        return -1;
    }
    uint8_t st;
    uint8_t len;
    if (recv_raw(c, &st, &len) < 0)
    {
        perror("recv()failed—no response from management server");
        return -1;
    }
    puts(status_to_str(st));
    c->authenticated = (st == STATUS_OK);
    return c->authenticated ? 0 : -1;
}
/* -------------------------------------------------------------------------- */
/* handlers                                                                   */
static int h_stats(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t len;
    if (send_raw(c, CMD_STATS, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, &len) < 0) return -1;
    if (st != STATUS_OK || len != STATS_PAYLOAD_BYTES)
    {
        puts(status_to_str(st));
        return -1;
    }
    uint32_t *v = (uint32_t *)read_buffer;
    printf("Opened : %u\n", ntohl(v[0]));
    printf("Closed : %u\n", ntohl(v[1]));
    printf("Current: %u\n", ntohl(v[2]));
    printf("Client : %u\n", ntohl(v[3]));
    printf("Origin : %u\n", ntohl(v[4]));
    return 0;
}

static int h_list(mgmt_client_t *c)
{
    uint32_t offset = 0;
    int has_more_data = 1;
    int user_count = 0;

    printf("Users:\n");

    while (has_more_data) {
        uint32_t net_offset = htonl(offset);
        if (send_raw(c, CMD_LIST_USERS, (uint8_t *)&net_offset, sizeof(net_offset)) < 0) {
            perror("send_raw failed");
            return -1;
        }


        uint8_t st;
        uint8_t len;
        if (recv_raw(c, &st, &len) < 0) {
            perror("recv_raw failed");
            return -1;
        }

        if (st != STATUS_OK) {
            puts(status_to_str(st));
            return -1;
        }

        if (len < sizeof(uint32_t)) {
            puts("Error: Invalid list_users chunk from server.");
            return -1;
        }
        uint32_t next_offset_net;
        memcpy(&next_offset_net, read_buffer, sizeof(uint32_t));
        offset = ntohl(next_offset_net);

        if (len > sizeof(uint32_t)) {
            char *p = (char *)(read_buffer + sizeof(uint32_t));
            char *end = (char *)(read_buffer + len);

            while (p < end && *p) {
                printf("- %s\n", p);
                user_count++;
                p += strlen(p) + 1;
            }
        }


        has_more_data = (offset != 0);
    }

    printf("--- End of list (%d users) ---\n", user_count);
    return 0;
}

static int h_add(mgmt_client_t *c)
{
    char u[INPUT_LINE_BUF];
    char p[INPUT_LINE_BUF];
    if(read_line("New user: ", u, sizeof u)<0){
        return -1;
    };
    if(read_line("New pass: ", p, sizeof p)<0){
        return -1;
    };
    if (check_len("Username", u, MAX_USERNAME_LEN) ||
        check_len("Password", p, MAX_PASSWORD_LEN)) return -1;

    char pl[CREDENTIALS_BUF];
    snprintf(pl, sizeof pl, "%s:%s", u, p);
    if (send_raw(c, CMD_ADD_USER, (uint8_t *)pl, (uint8_t)strlen(pl)) < 0)
    {
        perror("send()failed—could not transmit Add‑User command");
        return -1;
    }
    uint8_t st;
    uint8_t len;
    if (recv_raw(c, &st , &len) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_del(mgmt_client_t *c)
{
    char u[INPUT_LINE_BUF];
    if(read_line("User delete: ", u, sizeof u)<0){
        return -1;
    };
    if (check_len("Username", u, MAX_USERNAME_LEN)) return -1;
    if (send_raw(c, CMD_DELETE_USER, (uint8_t *)u, (uint8_t)strlen(u)) < 0) return -1;
    uint8_t st;
    uint8_t len;

    if (recv_raw(c, &st, &len) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_chpwd(mgmt_client_t *c)
{
    char u[INPUT_LINE_BUF];
    char p[INPUT_LINE_BUF];
    if(read_line("User: ", u, sizeof u)<0){
        return -1;
    };
    if(read_line("New pass: ", p, sizeof p)<0){
        return -1;
    };
    if (check_len("Username", u, MAX_USERNAME_LEN) ||
        check_len("Password", p, MAX_PASSWORD_LEN)) return -1;

    char * pl = (char *)read_buffer;
    snprintf(pl, sizeof(read_buffer), "%s:%s", u, p);
    if (send_raw(c, CMD_CHANGE_PASSWORD, (uint8_t *)pl, (uint8_t)strlen(pl)) < 0) return -1;
    uint8_t st;
    uint8_t len;
    if (recv_raw(c, &st, &len) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_bufinfo(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t len;
    if (send_raw(c, CMD_GET_BUFFER_INFO, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, &len) < 0) return -1;
    if (st != STATUS_OK || len != sizeof(uint32_t))
    {
        puts(status_to_str(st));
        return -1;
    }
    printf("Current buffer size: %u bytes\n", ntohl(*(uint32_t *)read_buffer));
    return 0;
}

static int h_setbuf(mgmt_client_t *c)
{
    puts("Buffer sizes:");
    for (size_t i = 0; i < BUF_OPTIONS_COUNT; i++)
    {
        printf(" %zu) %u\n", i + 1, BUF_SIZE_OPTIONS[i]);
    }
    int idx = ask_choice("Choice: ", 1, BUF_OPTIONS_COUNT);
    if(idx<0){
        return -1;
    }
    uint32_t net = htonl(BUF_SIZE_OPTIONS[idx - 1]);
    if (send_raw(c, CMD_SET_BUFFER_SIZE, (uint8_t *)&net, sizeof net) < 0) return -1;
    uint8_t st;
    uint8_t len;
    if (recv_raw(c, &st,  &len) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_setauth(mgmt_client_t *c)
{
    puts("1) NOAUTH\n2) AUTH");
    int opt = ask_choice("Choice: ", 1, 2);
    if(opt<0){
        return -1;
    }
    const char *m = opt == 1 ? "NOAUTH" : "AUTH";
    if (send_raw(c, CMD_SET_AUTH_METHOD, (uint8_t *)m, (uint8_t)strlen(m)) < 0) return -1;
    uint8_t st;
    uint8_t len;
    if (recv_raw(c, &st, &len) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_getauth(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t len;
    if (send_raw(c, CMD_GET_AUTH_METHOD, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st,  &len) < 0) return -1;
    if (st != STATUS_OK || len != 1)
    {
        puts(status_to_str(st));
        return -1;
    }
    puts(read_buffer[0] ? "AUTH" : "NOAUTH");
    return 0;
}

static int h_logs(mgmt_client_t *c)
{
    char u[INPUT_LINE_BUF];
    if(read_line("User (\"anonymous\" for NOAUTH): ", u, sizeof u) < 0) {
        return -1;
    }
    if (check_len("Username", u, MAX_USERNAME_LEN)) return -1;

    uint32_t offset = 0;
    int has_more_data = 1;

    printf("\n--- Logs for %s ---\n", u);

    while (has_more_data) {
        /* 1. Armar payload de la solicitud: [username]\0[offset] */
        uint8_t req_pl[MAX_USERNAME_LEN + 1 + sizeof(uint32_t)];
        size_t ulen = strlen(u);
        memcpy(req_pl, u, ulen);
        req_pl[ulen] = '\0'; // Añadir el NUL terminator

        uint32_t net_offset = htonl(offset);
        memcpy(req_pl + ulen + 1, &net_offset, sizeof(uint32_t));

        size_t req_len = ulen + 1 + sizeof(uint32_t);

        if (send_raw(c, CMD_GET_LOG_BY_USER, req_pl, req_len) < 0) return -1;

        /* 2. Recibir la respuesta del chunk */
        uint8_t st;
        uint8_t len;
        // LLAMADA CORREGIDA A recv_raw:
        if (recv_raw(c, &st, &len) < 0) { // Se debe pasar &st y &len. read_buffer es global.
            perror("recv_raw failed");
            return -1;
        }

        if (st != STATUS_OK) {
            puts(status_to_str(st));
            return -1;
        }

        if (len < sizeof(uint32_t)) {
            puts("Error: Invalid response chunk from server.");
            return -1;
        }

        /* 3. Extraer el 'next_offset' y los datos del log */
        uint32_t next_offset_net;
        memcpy(&next_offset_net, read_buffer, sizeof(uint32_t)); // Leer del buffer global
        offset = ntohl(next_offset_net);

        // Imprimir el contenido del log (el resto del payload)
        if (len > sizeof(uint32_t)) {
            fwrite(read_buffer + sizeof(uint32_t), 1, len - sizeof(uint32_t), stdout);
        }

        /* 4. Decidir si se necesita pedir otro chunk */
        has_more_data = (offset != 0);
    }

    printf("--- End of logs ---\n");
    return 0;
}
/* -------------------------------------------------------------------------- */
typedef int (*fn)(mgmt_client_t *);
typedef struct { const char *txt; fn f; } item;

static const fn MENU_FUNCS[] = {
        h_stats,
        h_list,
        h_add,
        h_del,
        h_chpwd,
        h_bufinfo,
        h_setbuf,
        h_setauth,
        h_getauth,
        h_logs,
        NULL  /* Disconnect */
};

#define MENU_COUNT (sizeof MENU_FUNCS / sizeof MENU_FUNCS[0])

static void draw_menu(void)
{
    puts("┌───────────────────────────────────────────────┐");
    puts("│ 1) Get Statistics            (CMD 0x02)       │");
    puts("│ 2) List Users                (CMD 0x03)       │");
    puts("│ 3) Add User                  (CMD 0x04)       │");
    puts("│ 4) Delete User               (CMD 0x05)       │");
    puts("│ 5) Change User Password      (CMD 0x06)       │");
    puts("│ 6) Get Buffer Info           (CMD 0x08)       │");
    puts("│ 7) Set Buffer Size           (CMD 0x07)       │");
    puts("│ 8) Change Authentication     (CMD 0x09)       │");
    puts("│ 9) Show Current Auth Method  (CMD 0x0A)       │");
    puts("│10) Show User Logs            (CMD 0x0B)       │");
    puts("│11) Disconnect                                 │");
    puts("└───────────────────────────────────────────────┘");
}
/* -------------------------------------------------------------------------- */
static void menu_loop(mgmt_client_t *c)
{
    while (1)
    {

        while (!c->authenticated)
        {
            puts("1) Connect & Authenticate\n2) Exit");
            int ask = ask_choice("Choice: ", 1, 2);
            if (ask == 2 || ask < 0) return;

            if (connect_server( c->server_host , c->server_port , &c->socket_fd) == 0) {
                auth_server(c);
            }

        }


        puts("\n=== Management Client ===");
        draw_menu();
        int ch = ask_choice("Choice: ", 1, MENU_COUNT);
        if (ch < 0) {
            disconnect(c);
            return;
        }

        fn handler = MENU_FUNCS[ch - 1];
        if (!handler) {
            disconnect(c);

            continue;
        }


        if (handler(c) < 0) {

            printf("Command failed. The connection may have been lost.\n");
            disconnect(c);

        }
    }
}


/* -------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    mgmt_client_t cli = { .socket_fd = -1, .authenticated = 0 };
    prompt_server_config(cli.server_host,sizeof cli.server_host,&cli.server_port, true);
    menu_loop(&cli);
    disconnect(&cli);
    return 0;
}
