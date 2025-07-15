#ifndef STATISTICS_H
#define STATISTICS_H

#include <stdint.h>

/* Contadores globales */
struct stats {
    unsigned hist_conn;
    unsigned curr_conn;
    unsigned max_conn;
    unsigned bytes_c2o;
    unsigned bytes_o2c;
};

extern struct stats g_stats;

/* solo prototypes */
void stats_connection_opened(void);
void stats_connection_closed(void);
void stats_add_client_bytes(unsigned n);
void stats_add_origin_bytes(unsigned n);

unsigned stats_get_connections_opened(void);
unsigned stats_get_connections_closed(void);
unsigned stats_get_current_connections(void);
unsigned stats_get_max_connections(void);
unsigned stats_get_client_bytes(void);
unsigned stats_get_origin_bytes(void);

void stats_print();

#endif /* STATISTICS_H */
