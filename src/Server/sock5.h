
#ifndef SOCK5_H
#define SOCK5_H
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "selector.h"
#include "stm.h"
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "buffer.h"
#include "Negotiation/negotiation.h"
#include "Negotiation/negotiation_parser.h"
#include "Auth/auth_parser.h"
#include "Auth/auth.h"
#include "Statistics/statistics.h"
#include "Resolver/resolver_parser.h"
#include "args.h"
#include "Copy/copy.h"
#include "ManagementProtocol/management.h"
#include "constants.h"
#include <time.h>
#include "selector.h"



#define BUFFER_SIZE BUFFER_SIZE_32K

struct users* get_authorized_users(void);
int get_num_authorized_users(void);

bool delete_user(const char* username);

struct dns_request {
    struct gaicb req;
    struct client_data * client_data;
    fd_selector selector;
    struct addrinfo hints;
    int fd;
    char port[6];
};
typedef struct client_data {
    struct state_machine stm;
    struct sockaddr_storage client_address;
    bool closed;
    union {
        negotiation_parser  neg_parser;
        auth_parser auth_parser;
        resolver_parser req_parser;
    } client;
    struct addrinfo* origin_resolution;
    struct addrinfo* current_resolution;
    bool resolution_from_getaddrinfo;
    int client_fd;
    int origin_fd;
    struct  dns_request dns_req;
    int dns_resolution_state;
    struct buffer client_buffer;
    struct buffer origin_buffer;
    uint8_t *in_client_buffer;
    uint8_t *in_origin_buffer;
    size_t buffer_size;
    bool unregistering_origin;
    bool auth_failed;
    time_t last_activity;
    user_t * user;
    char client_ip[INET6_ADDRSTRLEN];
    int client_port;
    char target_host[MAX_HOSTNAME_LEN];
    int target_port;
    uint8_t socks_status;

}client_data;

enum socks5State {
    NEGOTIATION_READ = 0,
    NEGOTIATION_WRITE,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    AUTHENTICATION_FAILURE_WRITE,
    REQ_READ,
    ADDR_RESOLVE,
    CONNECTING,
    REQ_WRITE,
    COPYING,
    CLOSED,
    ERROR
};
void socksv5_passive_accept(struct selector_key* key);
void close_connection(struct selector_key *key);
fd_handler * get_socksv5_handler(void);

void log_access_record(client_data *client_data);


#endif
