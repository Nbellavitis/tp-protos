#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

// Niveles de log
#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARN  1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DEBUG 3

// Nivel por defecto si no está definido
#ifdef DEBUG
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

// Función auxiliar inline para evitar problemas con variádicas
static inline void _log_print(FILE *stream, const char *tag, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stream, "[%s] ", tag);
    vfprintf(stream, fmt, args);
    fprintf(stream, "\n");
    va_end(args);
}

// Macros por nivel de log
#if LOG_LEVEL >= LOG_LEVEL_ERROR
#  define LOG_ERROR(...) _log_print(stderr, "ERROR", __VA_ARGS__)
#else
#  define LOG_ERROR(...) ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#  define LOG_WARN(...)  _log_print(stderr, "WARN", __VA_ARGS__)
#else
#  define LOG_WARN(...)  ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#  define LOG_INFO(...)  _log_print(stderr, "INFO", __VA_ARGS__)
#else
#  define LOG_INFO(...)  ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#  define LOG_DEBUG(...) _log_print(stderr, "DEBUG", __VA_ARGS__)
#else
#  define LOG_DEBUG(...) ((void)0)
#endif

#endif // LOGGER_H
