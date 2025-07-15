#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MAXPENDING              10
#define SELECTOR_TIMEOUT_SEC    10

// Network protocol constants (used across multiple modules)
#define IPV4_ADDR_SIZE          4
#define IPV6_ADDR_SIZE          16

#define BUFFER_SIZE_4K          4096
#define BUFFER_SIZE_8K          8192
#define BUFFER_SIZE_16K         16384
#define BUFFER_SIZE_32K         32768
#define BUFFER_SIZE_64K         65536
#define BUFFER_SIZE_128K        131072

#define COPY_BUFFER_SIZE        4096

#define TIMESTAMP_BUFFER_SIZE   32
#define LOG_LINE_SIZE           256

#endif // CONSTANTS_H