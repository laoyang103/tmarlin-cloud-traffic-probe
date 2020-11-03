#ifndef _DISP_UTIL_H_
#define _DISP_UTIL_H_

#include "global_define.h"

int initDispGlobalValue();
int getTime(const char *str, time_t *tt);
float avgFloatValue(float f1, float f2);
void getStrIP(u_int32_t addr, char *str);
void getDispStrTime(time_t tt, char *str);
void getDispTraffic(u_int32_t bytes, char *out);
void getDispPkts(u_int32_t pkts, char *out);
u_int32_t getDispIPFromStr(const char *str);
void getFilter(const char *str);

#endif
