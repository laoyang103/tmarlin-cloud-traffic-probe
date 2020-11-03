#ifndef _UI_H_
#define _UI_H_

#include "global_define.h"

int initUI();
void printTop(CommMsgT *list, int size, CommMsg6T *list6, int size6, int bytes, int pkt, int session, float rtt, float resp, float lose);

#endif
