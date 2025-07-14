//
// Created by lulos on 7/14/2025.
//
#include "management.h"

#ifndef MANAGEMENT_CMDS_H
#define MANAGEMENT_CMDS_H

typedef struct ManagementData ManagementData;

/* Prototype de un handler de comando */
typedef void (*mgmt_cmd_fn)(ManagementData *);


void mgmt_dispatch_command(ManagementData *md);

/* Declaración individual de cada handler  */


#endif
