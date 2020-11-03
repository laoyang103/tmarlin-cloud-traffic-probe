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

#include "disp-util.h"

extern DispReadOnlyGlobalT dispReadOnlyGlobal;
extern DispGlobalValueT dispGlobalValue;

int initDispGlobalValue()
{
  memset(&dispGlobalValue, 0x00, sizeof(DispGlobalValueT));
  dispGlobalValue.pCommValue = (CommValueT*)malloc(MAX_COMM_VALUE * sizeof(CommValueT));
  if(dispGlobalValue.pCommValue == 0)
    return -1;
  dispGlobalValue.pCommValue6 = (CommValue6T*)malloc(MAX_COMM_VALUE * sizeof(CommValue6T));
  if(dispGlobalValue.pCommValue6 == 0)
    return -1;
  dispGlobalValue.pBssValue = (BssValueT*)malloc(MAX_COMM_VALUE * sizeof(BssValueT));
  if(dispGlobalValue.pBssValue == 0)
    return -1;
  return 0;
}

int isNumeric(const char *str)
{
  int i, len;

  len = strlen(str);
  for(i = 0; i < len; i++){
    if(str[i] < '0')
      return 0;
    if(str[i] > '9')
      return 0;
  }
  return 1;
}

int getTime(const char *str, time_t *tt)
{
  int i, len, v, y, m, d, h, mi, s, split;
  char *p, buf[1024];
  time_t tcurr;
  struct tm stm;

  h = 0, mi = 0, s = 0;
  y = 0, m = 0, d = 0;
  strcpy(buf, str);
  len = strlen(buf);
  buf[len] = ':';
  len++;
  buf[len] = 0;
  p = buf;
  v = 0;
  for(i = 0; i < len; i++){
    split = 0;
    if(buf[i] == ':')
      split = 1;
    if(buf[i] == '-')
      split = 1;
    if(buf[i] == ' ')
      split = 1;
    if(split == 0)
      continue;
    v++;
    buf[i] = 0;
    if(v == 1)
      y = atoi(p);
    if(v == 2)
      m = atoi(p);
    if(v == 3)
      d = atoi(p);
    if(v == 4)
      h = atoi(p);
    if(v == 5)
      mi = atoi(p);
    if(v == 6)
      s = atoi(p);
    p = buf + i + 1;
  }
  if(v < 6)
    return -1;
  if(y < 1900)
    return -1;
  if((m <= 0) || (m > 12))
    return -1;
  if((d <= 0) || (d > 31))
    return -1;
  time(&tcurr);
  localtime_r(&tcurr, &stm);
  stm.tm_year = y - 1900;
  stm.tm_mon = m - 1;
  stm.tm_mday = d;
  stm.tm_hour = h;
  stm.tm_min = mi;
  stm.tm_sec = s;
  *tt = mktime(&stm);
  return 0;
}

float avgFloatValue(float f1, float f2)
{
  float fv;

  fv = (f1 + f2) / 2;
  return fv;
}

void getStrIP(u_int32_t addr, char *str)
{
  u_int32_t uv;

  uv = addr;
  sprintf(str, "%d.%d.%d.%d", uv/256/256/256, uv/256/256%256, uv/256%256, uv%256);
}

void getDispStrTime(time_t tt, char *str)
{
  struct tm stm;

  localtime_r(&tt, &stm);
  sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", stm.tm_year+1900, stm.tm_mon+1, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec);
}

void getDispTraffic(u_int32_t bytes, char *out)
{
  float dv;
  u_int32_t uv;

  uv = bytes * 8;
  if(uv < 1000){
    sprintf(out, "%d", uv);
    return;
  }
  dv = (float)bytes * 8;
  sprintf(out, "%.2fK", dv/1000);
  if(dv > 10000000.0) sprintf(out, "%.2fM", dv/1000000);
}

void getDispPkts(u_int32_t pkts, char *out)
{
  float dv;

  if(pkts < 1000){
    sprintf(out, "%d", pkts);
    return;
  }
  dv = (float)(pkts);
  sprintf(out, "%.2fK", dv/1000);
}

u_int32_t getDispIPFromStr(const char *str)
{
  char buf[1024];
  u_int32_t a, b, c, d, addr;

  strcpy(buf, str);
  if(sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d) != 4){
    return 0;
  }
  addr = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
  return addr;
}

int getSubnet1(const char *buf, u_int32_t *addressLow, u_int32_t *addressHigh)
{
  char *p;
  int bit, a, b, c, d;
  u_int32_t mask;

  p = strchr(buf, '/');
  if(p == 0){
    bit = 32;
  }else{
    *p = 0;
    p++;
    bit = atoi(p);
  }
  if(sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return -1;
  *addressLow = (((u_int32_t)a & 0xff) << 24) + (((u_int32_t)b & 0xff) << 16) + (((u_int32_t)c & 0xff) << 8) + ((u_int32_t)d & 0xff);
  if(bit >= 32){
    *addressHigh = *addressLow;
    return 0;
  }
  mask = 0xffffffff >> bit;
  mask = ~mask;
  if((*addressLow & mask) != *addressLow)
    return -1;
  mask = ~mask;
  *addressHigh = *addressLow | mask;
  return 0;
}

int getSubnet2(const char *str, u_int32_t *addressLow, u_int32_t *addressHigh)
{
  char *p, buf[1024];
  u_int32_t uv;

  strcpy(buf, str);
  p = strstr(buf, "-");
  if(!p)
    return 0;
  *p = 0;
  p++;
  if(*p == '-'){
    *p = 0;
    p++;
  }
  uv = getDispIPFromStr(buf);
  if(uv == 0)
    return -1;
  *addressLow = uv;
  uv = getDispIPFromStr(p);
  if(uv == 0)
    return -1;
  *addressHigh = uv;
  return 0;
}

int getOneFilter(const char *str, FilterInfoT *pFilter)
{
  int v;
  u_int32_t addr1, addr2;
  char buf[1024], *p;

  strcpy(buf, str);
  p = strstr(buf, "/");
  if(p){
    v = getSubnet1(buf, &addr1, &addr2);
    if(v < 0)
      return -1;
    pFilter->addressLow = addr1;
    pFilter->addressHigh = addr2;
    pFilter->port = 0;
    return 0;
  }
  p = strstr(buf, "-");
  if(p){
    v = getSubnet2(buf, &addr1, &addr2);
    if(v < 0)
      return -1;
    pFilter->addressLow = addr1;
    pFilter->addressHigh = addr2;
    pFilter->port = 0;
    return 0;
  }
  p = strstr(buf, ":");
  if(p){
    addr1 = getDispIPFromStr(buf);
    if(addr1 == 0)
      return -1;
    *p = 0;
    p++;
    pFilter->addressLow = addr1;
    pFilter->addressHigh = addr1;
    pFilter->port = atoi(p);
    return 0;
  }
  addr1 = getDispIPFromStr(buf);
  if(addr1 == 0)
    return -1;
  pFilter->addressLow = addr1;
  pFilter->addressHigh = addr1;
  pFilter->port = 0;
  return 0;
}

void getFilter(const char *str)
{
  int i, len, v;
  char buf[1024], *p;
  FilterInfoT filter;

  strcpy(buf, str);
  len = strlen(buf);
  buf[len] = ',';
  len++;
  buf[len] = 0;
  p = buf;
  for(i = 0; i < len; i++){
    if(buf[i] == ','){
      buf[i] = 0;
      if(isNumeric(p)){
        filter.addressLow = 0;
        filter.addressHigh = 0;
        filter.port = atoi(p);
        if(filter.port > 65535){
          printf("wrong port %s\n", p);
          continue;
        }
        memcpy(dispReadOnlyGlobal.filters + dispReadOnlyGlobal.cntFilter, &filter, sizeof(FilterInfoT));
        dispReadOnlyGlobal.cntFilter++;
      }
      v = getOneFilter(p, &filter);
      if(v < 0)
        printf("wrong filter condition %s\n", p);
      p = buf + i + 1;
      if(v < 0)
        continue;
      memcpy(dispReadOnlyGlobal.filters + dispReadOnlyGlobal.cntFilter, &filter, sizeof(FilterInfoT));
      dispReadOnlyGlobal.cntFilter++;
    }
  }
}
