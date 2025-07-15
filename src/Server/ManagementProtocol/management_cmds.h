#include "management.h"

#ifndef _MANAGEMENT_CMDS_H
#define _MANAGEMENT_CMDS_H

typedef struct ManagementData ManagementData;

typedef void (*mgmt_cmd_fn)(ManagementData *);


void mgmt_dispatch_command(ManagementData *md);



#endif
