#ifndef _I_NODE_H_
#define _I_NODE_H_

#include "global_define.h"

typedef struct _inode {
  u_int32_t local, remote;
  int localPort, remotePort, pid, proto;
  u_int64_t inode;
  char name[64], strCPU[64], strMEM[64];
} INodeT;

void initMapping();
void read_mapping();
int getProgInfo(CommMsgT *pCommMsg, int *pid, char *name, double *cpu, int *mem);
int getProgInfo2(NetSessionT *pSession, int *pid, char *name, double *cpu, int *mem);

#endif
