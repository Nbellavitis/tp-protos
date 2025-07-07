#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>





#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARN  1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DEBUG 3

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

#define _LOG_PRINT(stream, tag, fmt, ...) \
        fprintf(stream, "[" tag "] " fmt "\n", ##__VA_ARGS__)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#  define LOG_ERROR(fmt, ...) _LOG_PRINT(stderr, "ERROR", fmt, ##__VA_ARGS__)
#else
#  define LOG_ERROR(fmt, ...) ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#  define LOG_WARN(fmt, ...)  _LOG_PRINT(stderr, "WARN ", fmt, ##__VA_ARGS__)
#else
#  define LOG_WARN(fmt, ...)  ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#  define LOG_INFO(fmt, ...)  _LOG_PRINT(stderr, "INFO ", fmt, ##__VA_ARGS__)
#else
#  define LOG_INFO(fmt, ...)  ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#  define LOG_DEBUG(fmt, ...) _LOG_PRINT(stderr, "DEBUG", fmt, ##__VA_ARGS__)
#else
#  define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#endif
