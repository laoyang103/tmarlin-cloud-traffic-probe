/*
 * (C) 2013-2021 - tcpiplabs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "util.h"
#include "log.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

FILE *logFP;

int initLogFun()
{
  int year, month, day;

  logFP = 0;
  getCurrDate(&year, &month, &day);
  globalValue.currYear = year;
  globalValue.currMonth = month;
  globalValue.currDay = day;
  system("mkdir -p /var/log/Tmarlin");
  return 0;
}

FILE* openLogFile()
{
  FILE *fp;
  char buf[1024];
  int year, month, day;

  getCurrDate(&year, &month, &day);
  sprintf(buf, "/var/log/Tmarlin/Tmarlin.log.%d-%02d-%02d", year, month, day);
  fp = fopen(buf, "r+");
  if(fp == 0){
    fp = fopen(buf, "w");
    return fp;
  }
  fseek(fp, 0, SEEK_END);
  return fp;
}

void getDateTime(char *str)
{
  time_t tt;
  struct tm stm;
  int yy, mm, dd, hh, mi, ss;

  time(&tt);
  localtime_r(&tt, &stm);
  yy = stm.tm_year + 1900;
  mm = stm.tm_mon + 1;
  dd = stm.tm_mday;
  hh = stm.tm_hour;
  mi = stm.tm_min;
  ss = stm.tm_sec;
  sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", yy, mm, dd, hh, mi, ss);
}

void writeLog(int level, const char * format, ...)
{
  int len;
  va_list va_ap;
  char *p, buf[4096];

  if(logFP == 0)
    logFP = openLogFile();
  getDateTime(buf);
  if(level == PROBE_LOG_MESSAGE)
    strcat(buf, " MESSAGE: ");
  if(level == PROBE_LOG_WARNING)
    strcat(buf, " WARNING: ");
  if(level == PROBE_LOG_ERROR)
    strcat(buf, " ERROR: ");
  len = strlen(buf);
  p = buf + len;
  va_start(va_ap, format);
  vsprintf(p, format, va_ap);
  va_end(va_ap);
  len = strlen(buf);
  printf("%s\n", buf);
  if(NULL == logFP) return;
  len = fwrite(buf, len, 1, logFP);
  if(len <= 0){
    fclose(logFP);
    logFP = 0;
  }
  fflush(logFP);
}

void writeFileLogScreen(int level, const char * format, ...)
{
  int len;
  va_list va_ap;
  char *p, buf[4096];

  if(logFP == 0)
    logFP = openLogFile();
  if(logFP == 0)
    return;
  getDateTime(buf);
  if(level == PROBE_LOG_MESSAGE)
    strcat(buf, " MESSAGE: ");
  if(level == PROBE_LOG_WARNING)
    strcat(buf, " WARNING: ");
  if(level == PROBE_LOG_ERROR)
    strcat(buf, " ERROR: ");
  len = strlen(buf);
  p = buf + len;
  va_start(va_ap, format);
  vsprintf(p, format, va_ap);
  va_end(va_ap);
  len = strlen(buf);
  buf[len] = '\n';
  len++;
  buf[len] = 0;
  len = fwrite(buf, len, 1, logFP);
  if(len <= 0){
    fclose(logFP);
    logFP = 0;
  }
  fflush(logFP);
}

void checkLog()
{
  int year, month, day, v;

  v = 0;
  getCurrDate(&year, &month, &day);
  if(year != globalValue.currYear)
    v = 1;
  if(month != globalValue.currMonth)
    v = 1;
  if(day != globalValue.currDay)
    v = 1;
  if(v){
    if(logFP)
      fclose(logFP);
    logFP = 0;
  }
  globalValue.currYear = year;
  globalValue.currMonth = month;
  globalValue.currDay = day;
}
