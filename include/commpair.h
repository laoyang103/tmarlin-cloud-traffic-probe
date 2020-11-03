#ifndef _COMMPAIR_H_
#define _COMMPAIR_H_

#define  COMMPAIR_HASH_LENGTH                 16
#define  COMMPAIR_HASH_SIZE                   512

#include "comm.h"

typedef struct {
  CommMsgT commpair[COMMPAIR_HASH_LENGTH];
} CommPairHashNodeT;

typedef struct {
  CommPairHashNodeT node[COMMPAIR_HASH_SIZE];
} CommPairHashTableT;

typedef struct {
  CommMsg6T commpair[COMMPAIR_HASH_LENGTH];
} CommPairHashNode6T;

typedef struct {
  CommPairHashNode6T node[COMMPAIR_HASH_SIZE];
} CommPairHashTable6T;

int initCommPair();
void eraseCommpairTable();
void putCommpairSession(CommMsgT *pCommMsg);
void putCommpairSession6(CommMsg6T *pCommMsg);
void exportCommpairData(time_t tcurr);
void exportCommpairData6(time_t tcurr);

#endif
