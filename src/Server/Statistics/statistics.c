#include "statistics.h"
#include <stdio.h>
#include "../../logger.h"

struct stats g_stats = {0};

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
    LOG_INFO("%s" , "=== SOCKS5 STATISTICS ===");
    LOG_INFO("Conexiones históricas : %u", g_stats.hist_conn);
    LOG_INFO("Conexiones actuales   : %u", g_stats.curr_conn);
    LOG_INFO("Pico de conexiones    : %u", g_stats.max_conn);
    LOG_INFO("Bytes CLI → ORI       : %u", g_stats.bytes_c2o);
    LOG_INFO("Bytes ORI → CLI       : %u", g_stats.bytes_o2c);
}