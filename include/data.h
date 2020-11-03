#ifndef _DATA_H_
#define _DATA_H_

#include "global_define.h"

int initExpSock();
int initPacketSock();
int reOpenExpSock();
int reOpenPacketSock();
int exportPacketData(const struct pcap_pkthdr *h, const u_char *sp);
int exportData(CommMsgT *pCommMsg, time_t stamp);
int exportData6(CommMsg6T *pCommMsg, time_t stamp);
int exportBusinessData(NetSessionT *pNetSession);
void exportEndData(time_t tcurr);

#endif
