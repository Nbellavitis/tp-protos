//
// Created by nicke on 24/6/2025.
//

#ifndef PROTOS_TCPUTILS_H
#define PROTOS_TCPUTILS_H

#include <stdio.h>
#include <sys/socket.h>
#include <stdio.h>

// Create, bind, and listen a new TCP server socket
int setupTCPServerSocket(const char *service);

// Accept a new TCP connection on a server socket
int acceptTCPConnection(int servSock);

// Handle new TCP client
int handleTCPEchoClient(int clntSocket);

#endif //PROTOS_TCPUTILS_H
