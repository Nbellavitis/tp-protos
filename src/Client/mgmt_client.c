#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Server/ManagementProtocol/management.h"

/* -------------------------------------------------------------------------- */
#define DEFAULT_MGMT_HOST "127.0.0.1"
#define DEFAULT_MGMT_PORT 8080
#define RESPONSE_BUFFER_SIZE 1024
#define RESP_BUF 526
/* -------------------------------------------------------------------------- */

typedef struct
{
    int socket_fd;
    char server_host[256];
    int server_port;
    int authenticated;
} mgmt_client_t;
/* -------------------------------------------------------------------------- */
/* helpers de entrada */
static void read_line(const char *p, char *b, size_t n)
{
    printf("%s", p);
    if (!fgets(b, (int)n, stdin))
    {
        puts("\nEOF");
        exit(0);
    }
    b[strcspn(b, "\n")] = 0;
}

static int ask_choice(const char *p, int mn, int mx)
{
    char l[32];
    int v;
    for (;;)
    {
        read_line(p, l, sizeof l);
        v = atoi(l);
        if (v >= mn && v <= mx) return v;
        printf("Value %d‑%d\n", mn, mx);
    }
}

static int check_len(const char *lbl, const char *s, size_t m)
{
    if (strlen(s) > m)
    {
        printf("%s too long (>%zu)\n", lbl, m);
        return -1;
    }
    return 0;
}
/* -------------------------------------------------------------------------- */
/* status legible */
static const char *status_to_str(uint8_t st)
{
    const char *tbl[] =
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
/* -------------------------------------------------------------------------- */
/* I/O RAW */
static int send_raw(mgmt_client_t *c, uint8_t cmd, const uint8_t *pl, uint8_t len)
{
    uint8_t msg[3 + 255];
    msg[0] = MANAGEMENT_VERSION;
    msg[1] = cmd;
    msg[2] = len;
    if (len) memcpy(msg + 3, pl, len);
    return send(c->socket_fd, msg, 3 + len, MSG_NOSIGNAL) == 3 + len ? 0 : -1;
}

static int recv_raw(mgmt_client_t *c, uint8_t *st, uint8_t *pl, uint8_t *len)
{
    uint8_t h[3];
    if (read(c->socket_fd, h, 3) != 3) return -1;
    if (h[0] != MANAGEMENT_VERSION) return -1;
    *st = h[1];
    *len = h[2];
    if (*len && read(c->socket_fd, pl, *len) != *len) return -1;
    return 0;
}
/* -------------------------------------------------------------------------- */
/* conexión + auth */
static void disconnect(mgmt_client_t *c)
{
    if (c->socket_fd >= 0) close(c->socket_fd);
    c->socket_fd = -1;
    c->authenticated = 0;
}

static int connect_server(mgmt_client_t *c)
{
    c->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->socket_fd < 0)
    {
        perror("socket");       //@todo ser mas descriptivo.
        return -1;
    }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(c->server_port) };
    if (inet_pton(AF_INET, c->server_host, &sa.sin_addr) <= 0)
    {
        perror("inet_pton");
        disconnect(c);
        return -1;
    }
    if (connect(c->socket_fd, (struct sockaddr *)&sa, sizeof sa) < 0)
    {
        perror("connect");
        disconnect(c);
        return -1;
    }
    printf("Connected to %s:%d\n", c->server_host, c->server_port);
    return 0;
}

static int auth_server(mgmt_client_t *c)
{
    char u[128];
    char p[128];
    read_line("Username: ", u, sizeof u);
    read_line("Password: ", p, sizeof p);
    if (check_len("Username", u, MAX_USERNAME_LEN) || check_len("Password", p, MAX_PASSWORD_LEN))
        return -1;
    char cr[256];
    snprintf(cr, sizeof cr, "%s:%s", u, p);
    if (send_raw(c, CMD_AUTH, (uint8_t *)cr, (uint8_t)strlen(cr)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    c->authenticated = (st == STATUS_OK);
    return c->authenticated ? 0 : -1;
}
/* -------------------------------------------------------------------------- */
/* handlers */
static int h_stats(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t l;
    uint8_t p[20];
    if (send_raw(c, CMD_STATS, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, p, &l) < 0) return -1;
    if (st != STATUS_OK || l != 20)
    {
        puts(status_to_str(st));
        return -1;
    }
    uint32_t *v = (uint32_t *)p;
    printf("Opened : %u\n", ntohl(v[0]));
    printf("Closed : %u\n", ntohl(v[1]));
    printf("Current: %u\n", ntohl(v[2]));
    printf("Client : %u\n", ntohl(v[3]));
    printf("Origin : %u\n", ntohl(v[4]));
    return 0;
}

static int h_list(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t l;
    uint8_t p[RESP_BUF];
    if (send_raw(c, CMD_LIST_USERS, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, p, &l) < 0) return -1;
    if (st != STATUS_OK)
    {
        puts(status_to_str(st));
        return -1;
    }
    uint8_t n = p[0];
    char *q = (char *)(p + 1);
    printf("Users (%u):\n", n);
    for (uint8_t i = 0; i < n; i++)
    {
        printf("- %s\n", q);
        q += strlen(q) + 1;
    }
    return 0;
}

static int h_add(mgmt_client_t *c)
{
    char u[128];
    char p[128];
    read_line("New user: ", u, sizeof u);
    read_line("New pass: ", p, sizeof p);
    if (check_len("Username", u, MAX_USERNAME_LEN) || check_len("Password", p, MAX_PASSWORD_LEN))
        return -1;
    char pl[256];
    snprintf(pl, sizeof pl, "%s:%s", u, p);
    if (send_raw(c, CMD_ADD_USER, (uint8_t *)pl, (uint8_t)strlen(pl)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_del(mgmt_client_t *c)
{
    char u[128];
    read_line("User delete: ", u, sizeof u);
    if (check_len("Username", u, MAX_USERNAME_LEN)) return -1;
    if (send_raw(c, CMD_DELETE_USER, (uint8_t *)u, (uint8_t)strlen(u)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_chpwd(mgmt_client_t *c)
{
    char u[128];
    char p[128];
    read_line("User: ", u, sizeof u);
    read_line("New pass: ", p, sizeof p);
    if (check_len("Username", u, MAX_USERNAME_LEN) || check_len("Password", p, MAX_PASSWORD_LEN))
        return -1;
    char pl[256];
    snprintf(pl, sizeof pl, "%s:%s", u, p);
    if (send_raw(c, CMD_CHANGE_PASSWORD, (uint8_t *)pl, (uint8_t)strlen(pl)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_bufinfo(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t l;
    uint8_t p[4];
    if (send_raw(c, CMD_GET_BUFFER_INFO, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, p, &l) < 0) return -1;
    if (st != STATUS_OK || l != 4)
    {
        puts(status_to_str(st));
        return -1;
    }
    printf("Current buffer size: %u bytes\n", ntohl(*(uint32_t *)p));
    return 0;
}

static int h_setbuf(mgmt_client_t *c)
{
    const uint32_t sz[] = { 4096, 8192, 16384, 32768, 65536, 131072 };
    puts("Buffer sizes:\n");
    for (int i = 0; i < 6; i++)
    {
        printf(" %d) %u\n", i + 1, sz[i]);
    }
    int idx = ask_choice("Choice: ", 1, 6);
    uint32_t net = htonl(sz[idx - 1]);
    if (send_raw(c, CMD_SET_BUFFER_SIZE, (uint8_t *)&net, 4) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_setauth(mgmt_client_t *c)
{
    puts("1) NOAUTH\n2) AUTH\n");
    int opt = ask_choice("Choice: ", 1, 2);
    const char *m = opt == 1 ? "NOAUTH" : "AUTH";
    if (send_raw(c, CMD_SET_AUTH_METHOD, (uint8_t *)m, (uint8_t)strlen(m)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    uint8_t b[1];
    if (recv_raw(c, &st, b, &l) < 0) return -1;
    puts(status_to_str(st));
    return st == STATUS_OK ? 0 : -1;
}

static int h_getauth(mgmt_client_t *c)
{
    uint8_t st;
    uint8_t l;
    uint8_t p[1];
    if (send_raw(c, CMD_GET_AUTH_METHOD, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, p, &l) < 0) return -1;
    if (st != STATUS_OK || l != 1)
    {
        puts(status_to_str(st));
        return -1;
    }
    puts(p[0] ? "AUTH" : "NOAUTH");
    return 0;
}

static int h_logs(mgmt_client_t *c)
{
    char u[128];
    read_line("User (\"anonymous\" for NOAUTH): ", u, sizeof u);
    if (check_len("Username", u, MAX_USERNAME_LEN)) return -1;
    if (send_raw(c, CMD_GET_LOG_BY_USER, (uint8_t *)u, (uint8_t)strlen(u)) < 0) return -1;
    uint8_t st;
    uint8_t l;
    char resp[RESPONSE_BUFFER_SIZE];
    if (recv_raw(c, &st, (uint8_t *)resp, &l) < 0) return -1;
    if (st != STATUS_OK)
    {
        puts(status_to_str(st));
        return -1;
    }
    resp[l] = '\0';
    printf("\n%s\n", resp);
    return 0;
}
/* -------------------------------------------------------------------------- */
/* tabla menú + draw */
typedef int (*fn)(mgmt_client_t *);
typedef struct { const char *txt; fn f; } item;
static const item menu[] =
        {
                { "Get Statistics",            h_stats },
                { "List Users",                h_list },
                { "Add User",                  h_add },
                { "Delete User",               h_del },
                { "Change User Password",      h_chpwd },
                { "Get Buffer Info",           h_bufinfo },
                { "Set Buffer Size",           h_setbuf },
                { "Change Authentication",     h_setauth },
                { "Show Current Auth Method",  h_getauth },
                { "Show User Logs",            h_logs },
                { "Disconnect",                NULL }
        };
#define MENU_N (sizeof menu / sizeof menu[0])

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

    while (!c->authenticated)
    {
        puts("1) Connect & Authenticate\n2) Exit\n");
        if(ask_choice("Choice: ", 1, 2) == 2){
            return;
        }
        if (connect_server(c) == 0) auth_server(c);
    }

    while (1)
    {
        puts("\n=== Management Client ===\n");

        draw_menu();
        int cho = ask_choice("Choice: ", 1, MENU_N);
        if (!menu[cho - 1].f)
        {
            disconnect(c);
            puts("Disconnected.\n");
            break;
        }
        menu[cho - 1].f(c);
    }
}
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    mgmt_client_t cli = { .socket_fd = -1, .authenticated = 0 };
    strcpy(cli.server_host, (argc >= 2) ? argv[1] : DEFAULT_MGMT_HOST);
    cli.server_port = (argc >= 3) ? atoi(argv[2]) : DEFAULT_MGMT_PORT;
    menu_loop(&cli);
    disconnect(&cli);
    return 0;
}
