
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Niveles de log: se define UNO solo de estos a la vez, por ejemplo:
// #define LOG_LEVEL_INFO
// Por defecto se usa INFO si no se define nada

#if !defined(LOG_LEVEL_ERROR) && !defined(LOG_LEVEL_WARN) && \
    !defined(LOG_LEVEL_INFO) && !defined(LOG_LEVEL_DEBUG)
#define LOG_LEVEL_INFO
#endif

// =======================
// Logging Macros
// =======================

#ifdef LOG_LEVEL_ERROR
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_ERROR(fmt, ...)
#endif

#if defined(LOG_LEVEL_WARN) || defined(LOG_LEVEL_INFO) || defined(LOG_LEVEL_DEBUG)
#define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_WARN(fmt, ...)
#endif

#if defined(LOG_LEVEL_INFO) || defined(LOG_LEVEL_DEBUG)
#define LOG_INFO(fmt, ...) fprintf(stdout, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#endif

#ifdef LOG_LEVEL_DEBUG
#define LOG_DEBUG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#endif

#endif // LOGGER_H