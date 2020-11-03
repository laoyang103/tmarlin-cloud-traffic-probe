#ifndef _STORE_H_
#define _STORE_H_

#include <time.h>

#define  STORE_ERROR_WRONG_DIRECTIONARY               -1
#define  STORE_ERROR_SYSTEM_FAILED                    -2
#define  STORE_ERROR_NO_SPACE                         -3

int initStorePkts(const char *path, int space);
int initStoreJson(const char *path, int space);
void dumpPkt(const struct pcap_pkthdr *h, const u_char *pkt);
void writeJson(const char *str, time_t tt);
void dumpPktEnd();
void writeJsonEnd();

#endif

