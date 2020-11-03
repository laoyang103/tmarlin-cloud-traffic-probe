#ifndef _PLAY_H_
#define _PLAY_H_

#include "global_define.h"

#define  MAX_PCAPFILE_COUNT              64

typedef struct {
  int fd, cntFile;
  time_t tstart, tend;
  struct sockaddr_in expAddr;
  u_int32_t addr;
  char pcapPath[32];
  char pcapFile[MAX_FILE_COUNT][32];
  time_t ftime[MAX_FILE_COUNT];
} PlayGlobalT;

int playmain(int argc, char *argv[]);

#endif
