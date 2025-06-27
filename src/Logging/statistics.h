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

extern struct stats g_stats;   //@Todo, esto es porque lo hice gloabal. ver

/* solo prototypes */
void stats_connection_opened(void);
void stats_connection_closed(void);
void stats_add_client_bytes(unsigned n);
void stats_add_origin_bytes(unsigned n);



void stats_print();

#endif /* STATISTICS_H */
