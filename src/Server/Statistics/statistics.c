//
// Created by lulos on 6/27/2025.
//

#include "statistics.h"
#include <stdio.h>

struct stats g_stats = {0};  //todo por ahora los hice gloables, es algo malo eso?

void stats_connection_opened(void) {
    g_stats.hist_conn++;
    g_stats.curr_conn++;
    if (g_stats.curr_conn > g_stats.max_conn)
        g_stats.max_conn = g_stats.curr_conn;
}

void stats_connection_closed(void) {
    if (g_stats.curr_conn)
        g_stats.curr_conn--;
}

void stats_add_client_bytes(unsigned n) {
    g_stats.bytes_c2o += n;
}

void stats_add_origin_bytes(unsigned n) {
    g_stats.bytes_o2c += n;
}

// Getters para las estadísticas
unsigned stats_get_connections_opened(void) {
    return g_stats.hist_conn;
}

unsigned stats_get_connections_closed(void) {
    return g_stats.hist_conn - g_stats.curr_conn;
}

unsigned stats_get_current_connections(void) {
    return g_stats.curr_conn;
}

unsigned stats_get_max_connections(void) {
    return g_stats.max_conn;
}

unsigned stats_get_client_bytes(void) {
    return g_stats.bytes_c2o;
}

unsigned stats_get_origin_bytes(void) {
    return g_stats.bytes_o2c;
}

void stats_print()
{

    fprintf(stdout,
            "=== SOCKS5 STATISTICS ===\n"
            "Conexiones históricas : %u\n"
            "Conexiones actuales   : %u\n"
            "Pico de conexiones    : %u\n"
            "Bytes CLI → ORI       : %u\n"
            "Bytes ORI → CLI       : %u\n",
            g_stats.hist_conn,
            g_stats.curr_conn,
            g_stats.max_conn,
            g_stats.bytes_c2o,
            g_stats.bytes_o2c);
}