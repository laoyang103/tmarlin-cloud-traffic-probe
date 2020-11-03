#ifndef _LOG_H_
#define _LOG_H_

#include <stdarg.h>

#define  PROBE_LOG_MESSAGE     1
#define  PROBE_LOG_WARNING     2
#define  PROBE_LOG_ERROR       3

int initLogFun();
void writeLog(int level, const char * format, ...);
void writeFileLogScreen(int level, const char * format, ...);
void checkLog();

#endif
