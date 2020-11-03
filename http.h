#ifndef _HTTP_H_
#define _HTTP_H_

#include "util.h"

int isReqStart(const char *str, int strLen, char *url, char *method, char *domain, char *contentType, char *agent);
int isResStart(const char *str, int strLen, int *code);
int getForward(const char *str, int strlen, u_int32_t *forward);

#endif
