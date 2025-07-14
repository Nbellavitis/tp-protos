/*
 * Management Protocol CLI Client
 * (actualizado para STATUS expresivos y validación local)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Server/ManagementProtocol/management.h"

#define DEFAULT_MGMT_HOST "127.0.0.1"
#define DEFAULT_MGMT_PORT 8080

#define RESPONSE_BUFFER_SIZE 1024
#define RESP_BUF            526

/* ---------------- Comandos ---------------- */
#define CMD_AUTH             0x01
#define CMD_STATS            0x02
#define CMD_LIST_USERS       0x03
#define CMD_ADD_USER         0x04
#define CMD_DELETE_USER      0x05
#define CMD_CHANGE_PASSWORD  0x06
#define CMD_SET_BUFFER_SIZE  0x07
#define CMD_GET_BUFFER_INFO  0x08
#define CMD_SET_AUTH_METHOD  0x09
#define CMD_GET_AUTH_METHOD  0x0A
#define CMD_GET_LOG_BY_USER  0x0B

/* ---------------- Status codes ------------ */
#define STATUS_OK               0x00
#define STATUS_ERROR            0x01
#define STATUS_AUTH_REQUIRED    0x02
#define STATUS_AUTH_FAILED      0x03
#define STATUS_NOT_FOUND        0x04
#define STATUS_FULL             0x05
#define STATUS_INVALID_FORMAT   0x06
#define STATUS_LEN_EXCEEDED     0x07
#define STATUS_ALREADY_EXISTS   0x08
#define STATUS_NOT_ALLOWED      0x09
#define STATUS_RESERVED_USER    0x0A

typedef struct {
    int  socket_fd;
    char server_host[256];
    int  server_port;
    int  authenticated;
} mgmt_client_t;

/* ---------- status legible ---------- */
static const char *status_to_str(uint8_t st)
{
    switch (st) {
        case STATUS_OK:              return "Success";
        case STATUS_ERROR:           return "Error";
        case STATUS_AUTH_REQUIRED:   return "Auth required";
        case STATUS_AUTH_FAILED:     return "Auth failed";
        case STATUS_NOT_FOUND:       return "Not found";
        case STATUS_FULL:            return "Capacity full";
        case STATUS_INVALID_FORMAT:  return "Invalid format";
        case STATUS_LEN_EXCEEDED:    return "Length exceeded";
        case STATUS_ALREADY_EXISTS:  return "Already exists";
        case STATUS_NOT_ALLOWED:     return "Not allowed";
        case STATUS_RESERVED_USER:   return "Reserved user";
        default:                     return "Unknown status";
    }
}

/* ---------- I/O RAW helpers ---------- */
static int send_raw(mgmt_client_t *c, uint8_t cmd,
                    const uint8_t *pl, uint8_t len)
{
    uint8_t msg[3 + 255];
    msg[0] = MANAGEMENT_VERSION;
    msg[1] = cmd;
    msg[2] = len;
    if (len) memcpy(msg + 3, pl, len);

    return (send(c->socket_fd, msg, 3 + len, MSG_NOSIGNAL) == 3 + len) ? 0 : -1;
}

static int recv_raw(mgmt_client_t *c,
                    uint8_t *st, uint8_t *pl, uint8_t *len)
{
    uint8_t hdr[3];
    if (read(c->socket_fd, hdr, 3) != 3) return -1;
    if (hdr[0] != MANAGEMENT_VERSION)   return -1;

    *st  = hdr[1];
    *len = hdr[2];
    if (*len && read(c->socket_fd, pl, *len) != *len) return -1;
    return 0;
}

/* ---------- Conexión y auth ---------- */
static void disconnect(mgmt_client_t *c)
{
    if (c->socket_fd >= 0) close(c->socket_fd);
    c->socket_fd = -1; c->authenticated = 0;
}

static int connect_server(mgmt_client_t *c)
{
    c->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->socket_fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in sa = { .sin_family = AF_INET,
            .sin_port = htons(c->server_port) };
    if (inet_pton(AF_INET, c->server_host, &sa.sin_addr) <= 0) {
        perror("inet_pton"); disconnect(c); return -1; }

    if (connect(c->socket_fd,(struct sockaddr*)&sa,sizeof sa) < 0) {
        perror("connect"); disconnect(c); return -1; }

    printf("Connected to %s:%d\n", c->server_host, c->server_port);
    return 0;
}

static int auth_server(mgmt_client_t *c,
                       const char *u,const char *p)
{
    if (strlen(u) > MAX_USERNAME_LEN || strlen(p) > MAX_PASSWORD_LEN) {
        puts("Length exceeded");
        return -1;
    }
    char cred[256]; snprintf(cred,sizeof cred,"%s:%s",u,p);

    if (send_raw(c,CMD_AUTH,(uint8_t*)cred,(uint8_t)strlen(cred))<0) return -1;

    uint8_t st,len,buf[1];
    if (recv_raw(c,&st,buf,&len) < 0) return -1;
    puts(status_to_str(st));
    c->authenticated = (st==STATUS_OK);
    return c->authenticated?0:-1;
}

/* ---------- Comandos payload – stats, list, buffer, log ---------- */
static int cmd_stats(mgmt_client_t *c)
{
    uint8_t st,len,pl[20];
    if (send_raw(c,CMD_STATS,NULL,0) < 0) return -1;
    if (recv_raw(c,&st,pl,&len)     < 0) return -1;
    if (st!=STATUS_OK||len!=20){ puts(status_to_str(st)); return -1; }

    uint32_t *v=(uint32_t*)pl;
    printf("Opened : %u\nClosed : %u\nCurrent: %u\nClient : %u\nOrigin : %u\n",
           ntohl(v[0]),ntohl(v[1]),ntohl(v[2]),ntohl(v[3]),ntohl(v[4]));
    return 0;
}

static int cmd_list_users(mgmt_client_t *c)
{
    uint8_t st,len,pl[RESP_BUF];
    if (send_raw(c,CMD_LIST_USERS,NULL,0) < 0) return -1;
    if (recv_raw(c,&st,pl,&len)          < 0) return -1;
    if (st!=STATUS_OK){ puts(status_to_str(st)); return -1; }

    uint8_t n=pl[0]; char *p=(char*)(pl+1);
    printf("Users (%u):\n",n);
    for(uint8_t i=0;i<n;i++){ printf("  %s\n",p); p+=strlen(p)+1; }
    return 0;
}
//
//static int cmd_buffer_info(mgmt_client_t *c)
//{
//    uint8_t st,len,pl[64];
//    if (send_raw(c,CMD_GET_BUFFER_INFO,NULL,0) < 0) return -1;
//    if (recv_raw(c,&st,pl,&len)               < 0) return -1;
//    if (st!=STATUS_OK||len<5){ puts(status_to_str(st)); return -1;}
//
//    uint32_t cur=ntohl(*(uint32_t*)pl);
//    uint8_t n=pl[4]; printf("Current: %u\nAllowed:",cur);
//    for(uint8_t i=0;i<n;i++)
//        printf(" %u",ntohl(*(uint32_t*)(pl+5+i*4)));
//    puts("");
//    return 0;
//}

static int cmd_buffer_info(mgmt_client_t *c)
{
    uint8_t st,len,pl[4];
    if (send_raw(c, CMD_GET_BUFFER_INFO, NULL, 0) < 0) return -1;
    if (recv_raw(c, &st, pl, &len)                < 0) return -1;

    if (st != STATUS_OK || len != 4) { puts(status_to_str(st)); return -1; }

    uint32_t cur = ntohl(*(uint32_t *)pl);
    printf("Current buffer size: %u bytes\n", cur);
    return 0;
}

static int cmd_log_by_user(mgmt_client_t *c,const char *user)
{
    if (send_raw(c,CMD_GET_LOG_BY_USER,
                 (uint8_t*)user,(uint8_t)strlen(user))<0) return -1;

    uint8_t st,len; char resp[RESPONSE_BUFFER_SIZE];
    if (recv_raw(c,&st,(uint8_t*)resp,&len)<0) return -1;

    if (st!=STATUS_OK){ puts(status_to_str(st)); return -1; }
    resp[len]='\0';
    printf("Access log for %s:\n%s\n",user,resp);
    return 0;
}

/* ---------- Comandos sin payload – add/del/chpwd/buffer/auth -------- */
static int cmd_add_user(mgmt_client_t *c,const char *u,const char *p)
{
    if (strlen(u) > MAX_USERNAME_LEN || strlen(p) > MAX_PASSWORD_LEN){
        puts("Length exceeded"); return -1; }
    char pl[256]; snprintf(pl,sizeof pl,"%s:%s",u,p);

    if (send_raw(c,CMD_ADD_USER,(uint8_t*)pl,(uint8_t)strlen(pl))<0)return -1;
    uint8_t st,len,buf[1]; if (recv_raw(c,&st,buf,&len)<0) return -1;
    puts(status_to_str(st)); return (st==STATUS_OK)?0:-1;
}

static int cmd_delete_user(mgmt_client_t *c,const char *u)
{
    if (strlen(u) > MAX_USERNAME_LEN){ puts("Length exceeded"); return -1;}
    if (send_raw(c,CMD_DELETE_USER,(uint8_t*)u,(uint8_t)strlen(u))<0)return -1;
    uint8_t st,len,buf[1]; if (recv_raw(c,&st,buf,&len)<0) return -1;
    puts(status_to_str(st)); return (st==STATUS_OK)?0:-1;
}

static int cmd_change_pwd(mgmt_client_t *c,const char *u,const char *p)
{
    if (strlen(u) > MAX_USERNAME_LEN || strlen(p) > MAX_PASSWORD_LEN){
        puts("Length exceeded"); return -1;}
    char pl[256]; snprintf(pl,sizeof pl,"%s:%s",u,p);
    if (send_raw(c,CMD_CHANGE_PASSWORD,(uint8_t*)pl,(uint8_t)strlen(pl))<0)return -1;
    uint8_t st,len,buf[1]; if (recv_raw(c,&st,buf,&len)<0) return -1;
    puts(status_to_str(st)); return (st==STATUS_OK)?0:-1;
}

static int cmd_set_buffer(mgmt_client_t *c,uint32_t v)
{
    uint32_t net=htonl(v);
    if (send_raw(c,CMD_SET_BUFFER_SIZE,(uint8_t*)&net,4)<0) return -1;
    uint8_t st,len,buf[1]; if (recv_raw(c,&st,buf,&len)<0) return -1;
    puts(status_to_str(st)); return (st==STATUS_OK)?0:-1;
}

static int cmd_set_auth_method(mgmt_client_t *c,const char *m)
{
    if (send_raw(c,CMD_SET_AUTH_METHOD,(uint8_t*)m,(uint8_t)strlen(m))<0)return -1;
    uint8_t st,len,buf[1]; if (recv_raw(c,&st,buf,&len)<0) return -1;
    puts(status_to_str(st)); return (st==STATUS_OK)?0:-1;
}

static int cmd_get_auth_method(mgmt_client_t *c)
{
    uint8_t st,len,pl[1];
    if (send_raw(c,CMD_GET_AUTH_METHOD,NULL,0)<0) return -1;
    if (recv_raw(c,&st,pl,&len)              <0) return -1;
    if (st!=STATUS_OK||len!=1){ puts(status_to_str(st)); return -1;}
    puts(pl[0]==0x00?"NOAUTH":"AUTH"); return 0;
}

/* ---------- Menú interactivo ---------- */
static void menu(mgmt_client_t *c)
{
    char in[128], user[128], pass[128];

    while (1) {
        printf("\n=== Management Client ===\n");
        if (!c->authenticated) {
            puts("1) Connect & Auth\n2) Exit");
            printf("Choice: "); if (!fgets(in,sizeof in,stdin)) break;
            int ch=atoi(in);
            if (ch==1){
                if (connect_server(c)<0) continue;
                printf("Username: "); fgets(user,sizeof user,stdin);
                printf("Password: "); fgets(pass,sizeof pass,stdin);
                user[strcspn(user,"\n")]=0; pass[strcspn(pass,"\n")]=0;
                auth_server(c,user,pass);
            } else if (ch==2) break;
            continue;
        }

        /* --- menú para sesión autenticada --- */
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

        printf("Choice: ");
        if (!fgets(in,sizeof in,stdin)) break;
        int ch=atoi(in);
        switch(ch){
            case 1: cmd_stats(c); break;
            case 2: cmd_list_users(c); break;
            case 3:
                printf("New user: "); fgets(user,sizeof user,stdin);
                printf("New pass: "); fgets(pass,sizeof pass,stdin);
                user[strcspn(user,"\n")]=0; pass[strcspn(pass,"\n")]=0;
                cmd_add_user(c,user,pass); break;
            case 4:
                printf("User delete: "); fgets(user,sizeof user,stdin);
                user[strcspn(user,"\n")]=0; cmd_delete_user(c,user); break;
            case 5:
                printf("User: "); fgets(user,sizeof user,stdin);
                printf("New pass: "); fgets(pass,sizeof pass,stdin);
                user[strcspn(user,"\n")]=0; pass[strcspn(pass,"\n")]=0;
                cmd_change_pwd(c,user,pass); break;
            case 6: cmd_buffer_info(c); break;
            case 7:{
                const uint32_t sz[]={4096,8192,16384,32768,65536,131072};
                puts("1)4096\n2)8192\n3)16384\n4)32768\n5)65536\n6)131072");
                printf("Choice: "); fgets(in,sizeof in,stdin);
                int idx=atoi(in); if(idx<1||idx>6){puts("Invalid"); break;}
                cmd_set_buffer(c,sz[idx-1]); break;}
            case 8:
                puts("1)NOAUTH 2)AUTH"); printf("Choice: "); fgets(in,sizeof in,stdin);
                cmd_set_auth_method(c,(atoi(in)==1)?"NOAUTH":"AUTH"); break;
            case 9: cmd_get_auth_method(c); break;
            case 10:
                printf("User (\"anonymous\" for NOAUTH): "); fgets(user,sizeof user,stdin);
                user[strcspn(user,"\n")]=0; cmd_log_by_user(c,user); break;
            case 11: disconnect(c); puts("Disconnected."); return;
            default: puts("Invalid choice");
        }
    }
}

/* ---------- main ---------- */
int main(int argc,char *argv[])
{
    mgmt_client_t cli={.socket_fd=-1,.authenticated=0};
    strcpy(cli.server_host, (argc>=2)?argv[1]:DEFAULT_MGMT_HOST);
    cli.server_port = (argc>=3)?atoi(argv[2]):DEFAULT_MGMT_PORT;

    menu(&cli);
    disconnect(&cli);
    return 0;
}
