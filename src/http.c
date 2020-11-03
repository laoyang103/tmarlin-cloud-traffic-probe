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

extern ReadOnlyGlobalT readOnlyGlobal;

int getMethod(const char *str, char *method);
void getHttpFeature(char *str, char *domain, char *contentType, char *agent);

int isReqStart(const char *str, int strLen, char *url, char *method, char *domain, char *contentType, char *agent)
{
  int i, shift, v;
  char *p, *p1, buf[2048];

 v = getMethod(str, method);
  if(!v)
    return 0; // Check http method
  shift = 4;
  if(v == 2)
    shift = 5;
  if(v == 3)
    shift = 5;
  v = strLen - shift;
  if(v > 2040)
    v = 2040;
  strncpy(buf, str + shift, v);
  buf[v] = 0;
  p = strstr(buf, " HTTP");
  if(!p)
    return 0;  // Check http version
  getHttpFeature(p, domain, contentType, agent);

  *p = 0;
  p1 = buf;
  p = strstr(p1, "REFERER=");
  if(p)
    *p = 0;
  v = strlen(p1);
  if(v <= 0)
    return 0;
  if(!strncmp(p1, "http", 4)){
    p1 += 7;
    v = strlen(p1);
    for(i = 0; i < v; i++){
      if(p1[i] == '/')
        break;
      domain[i] = p1[i];
    }
    domain[i] = 0;
    strncpy(url, p1 + i, MAX_URL_LENGTH - 1);
    url[MAX_URL_LENGTH - 1] = 0;
    return 1;
  }
  strncpy(url, p1,  MAX_URL_LENGTH - 1);
  url[MAX_URL_LENGTH - 1] = 0;
  for(i = 0; i < v; i++){
    if((url[i] < 32) || (url[i] > 127)){
      url[i] = 0;
      break;
    }
    if(url[i] == '\'')
      url[i] = '"';
  }
  return 1;
}

int isResStart(const char *str, int strLen, int *code)  // Get http return code
{
  char *p, buf[1024];
  int i, len, v;

  v = strLen;
  if(v > 1000)
    v = 1000; 
  memset(buf, 0x00, 1024);
  strncpy(buf, str, v);
  if(strncmp(buf, "HTTP", 4))
    return 0;
  p = strstr(buf, "\r\n");
  if(!p)
    return 0;
  *p = 0;
  len = strlen(buf);
  v = -1;
  for(i = 0; i < len; i++){
    if(buf[i] == ' '){
      buf[i] = 0;
      if(v < 0)
        v = i + 1;
    }
  }
  *code = atoi(buf + v);
  return 1;
}

int getMethod(const char *str, char *method)
{
  if(!strncmp(str, "GET ", 4)){
    strcpy(method, "GET");
    return 1;
  }
  if(!strncmp(str, "POST ", 5)){
    strcpy(method, "POST");
    return 2;
  }
  if(!strncmp(str, "HEAD ", 5)){
    strcpy(method, "HEAD");
    return 3;
  }
  return 0;
}

int getForward(const char *str, int strLen, u_int32_t *forward)
{
  char *p, buf[1024];
  int i, len;

  p = strstr(str, "X-Forwarded-For: ");
  if(!p)
    return 0;
  p += 17;
  strncpy(buf, p, 1020);
  buf[1020] = 0;
  p = strstr(buf, "\r\n");
  if(!p)
    return 0;
  *p = 0;
  p = buf;
  len = strlen(buf);
  for(i = len -1; i >=0; i--){
    if(buf[i] == ','){
      p = buf + i + 1;
      break;
    }
  }
  getIPFromStr(p, forward);
  return 1;
}

void getValue(char *dst, char *src)
{
  int i;

  for(i = 0; i < 60; i++){
    dst[i] = src[i];
    if(src[i] == '"'){
      dst[i] = ' ';
      continue;
    }
    if(src[i] == ':'){
      dst[i] = ' ';
      continue;
    }
    if((src[i] == '=') && (i < 2)){
      dst[i] = ' ';
      continue;
    }
    if(src[i] == '&'){
      dst[i] = 0;
      break;
    }
    if(src[i] == ','){
      dst[i] = 0;
      break;
    }
    if(src[i] == ';'){
      dst[i] = 0;
      break;
    }
    if(src[i] == '\r'){
      dst[i] = 0;
      break;
    }
    if(src[i] == '\n'){
      dst[i] = 0;
      break;
    }
  }
  dst[i] = 0;
  trim(dst);
  return;
}

void getHttpFeature(char *str, char *domain, char *contentType, char *agent)  // Get HTTP features(host, agent, content-length)
{
  int i, len, v;
  char tmp[2048], *p, *p1;

  len = strlen(str);
  p = str;
  p1 = 0;
  v = 0;
  for(i = 0; i < len; i++){
    if(!strncmp(p + i, "\r\n\r\n", 4))
      v = 1;
    if(!strncmp(p + i, "\r\n", 2)){
      p[i] = 0;
      if(p1 != 0){
        strcpy(tmp, p1);
        if(!strncmp(tmp, "Host:", 5)){
          strncpy(domain, tmp + 6, 31);
          domain[31] = 0;
        }
        if(!strncmp(tmp, "User-Agent:", 11)){
          strncpy(agent, tmp + 12, 62);
          agent[62] = 0;
        }
        if(!strncmp(tmp, "Content-Type:", 13)){
          strncpy(contentType, tmp + 14, 62);
          contentType[62] = 0;
        }
      }
      p1 = p + i + 2;
    }
    if(v)
      return;
  }
}
