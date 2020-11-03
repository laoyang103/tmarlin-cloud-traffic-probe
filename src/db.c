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

void getStrSql(char *sql, u_char *payload, int payloadLen, int *real)  // get sql(oracle or mysql) string from payload of packet
{
  int i, j, len, iStart, flag;
  char buf[2048], *p1, *p2, ch;

  len = payloadLen;
  if(payloadLen > 2040)
    len = 2040;
  memcpy(buf, payload, len);
  buf[len] = 0;
  for(i = 0; i < len; i++){
    if(buf[i] < ' ')
      buf[i] = ' ';
  }
  toLowerCase(buf);
  p1 = 0;
  p2 = 0;
  p1 = strstr(buf, "select");
  if(p1)
    p2 = strstr(buf, "from");
  if(p1 == 0){
    p1 = strstr(buf, "insert");
    if(p1)
      p2 = strstr(buf, "into");
  }
  if(p1 == 0){
    p1 = strstr(buf, "update");
    if(p1)
      p2 = strstr(buf, "set");
  }
  if(p1 == 0){
    p1 = strstr(buf, "delete");
    if(p1)
      p2 = strstr(buf, "from");
  }
  if(p1 == 0)
    p1 = strstr(buf, "create");
  if(p1 == 0)
    p1 = strstr(buf, "analyze");
  if(p1 == 0)
    p1 = strstr(buf, "drop");
  if(p1 == 0)
    p1 = strstr(buf, "alter");
  if(p1 == 0)
    return;
  if(p2 != 0)
    *real = 1;
  iStart = p1 - buf;
  flag = 0;
  j = 0;
  for(i = iStart; i < payloadLen; i++){
    if(payload[i] == 0)
      break;
    ch = payload[i];
    if(ch == '\r')
      ch = ' ';
    if(ch == '\n')
      ch = ' ';
    if(ch == ' '){
      if(flag)
        continue;
      flag = 1;
    }else{
      flag = 0;
    }
    if(ch < 32)
      continue;
    sql[j] = ch;
    if(sql[j] == '"')
      sql[j] = '\'';
    j++;
    if(j > MAX_SQL_LENGTH - 4)
      break;
  }
  sql[j] = 0;
  trim(sql);
}

void getSqlserverSql(char *sql, u_char *payload, int payloadLen, int *real)  // get sql string of sqlserver from payload of packet
{
  int i, j, len, flag;
  char buf[2048], *p1, *p2, tmp[2048];

  j = 0;
  for(i = 0; i < payloadLen; i++){
    if(payload[i] == 0)
      continue;
    tmp[j] = (char)payload[i];
    if(tmp[j] < ' ')
      tmp[j] = ' ';
    j++;
    if(j > 2040)
      break;
  }
  tmp[j] = 0;
  strcpy(buf, tmp);
  toLowerCase(tmp);
  p1 = strstr(tmp, "select");
  if(p1)
    p2 = strstr(tmp, "from");
  if(p1 == 0){
    p1 = strstr(tmp, "insert");
    if(p1)
      p2 = strstr(tmp, "into");
  }
  if(p1 == 0){
    p1 = strstr(tmp, "update");
    if(p1)
      p2 = strstr(tmp, "set");
  }
  if(p1 == 0){
    p1 = strstr(tmp, "delete");
    if(p1)
      p2 = strstr(tmp, "from");
  }
  if(p1 == 0)
    p1 = strstr(buf, "create");
  if(p1 == 0)
    p1 = strstr(buf, "analyze");
  if(p1 == 0)
    return;
  if(p2 != 0)
    *real = 1;
  i = p1 - tmp;
  p2 = buf + i;
  len = strlen(buf + i);
  flag = 0;
  j = 0;
  for(i = 0; i < len; i++){
    if(p2[i] == 0)
      break;
    if((p2[i] == '\r') || (p2[i] == '\n') || (p2[i] == ' ')){
      if(flag)
        continue;
      flag = 1;
    }else{
      flag = 0;
    }
    sql[j] = p2[i];
    j++;
    if(j > MAX_SQL_LENGTH - 4)
      break;
  }
  sql[j] = 0;
  trim(sql);
}

void getOracleCode(int *code, char *errMess, u_char *payload, int payloadLen)
{
  int i, len;
  char buf[2048], *p1, *p2, tmp[128];

  len = payloadLen;
  if(payloadLen > 2040)
    len = 2040;
  memcpy(buf, payload, len);
  buf[len] = 0;
  for(i = 0; i < len; i++){
    if(buf[i] < ' ')
      buf[i] = ' ';
  }
  p1 = strstr(buf, "ORA-");
  if(p1){
    strncpy(tmp, p1 + 4, 5);
    tmp[5] = 0;
    *code = atoi(tmp);
    p2 = p1 + 10;
    strncpy(errMess, p2, 32);
    for(i = 0; i < 32; i++){
      if(errMess[i] == 10){
        errMess[i] = 0;
        break;
      }
    }
  }
  trim(errMess);
}

void getMysqlCode(int *code, char *errMess, u_char *payload, int payloadLen)
{
  int len, retCode;

  if(payloadLen < 5)
    return;
  if(payload[4] != 0xFF)
    return;
  retCode = 0;
  if(payloadLen < 7)
    return;
  retCode = (int)payload[6] * 256 + (int)payload[5];
  if(retCode > 1000)
    retCode = 0;
  *code = retCode;
  len = payloadLen - 13;
  if(len > 120)
    len = 120;
  if(payloadLen < (13+len))
    return;
  strncpy(errMess, (char*)payload + 13, len);
  errMess[len] = 0;
}

void getSqlserverCode(int *code, char *errMess, u_char *payload, int payloadLen)
{
  int len, retCode;

  if(payloadLen < 15)
    return;
  if(payload[8] != 170)
    return;
  retCode = (int)payload[14] * 256 * 256 * 256 + (int)payload[13] * 256 * 256 + (int)payload[12] * 256 + (int)payload[11];
  if(retCode > 20000)
    retCode = 0;
  len = payloadLen - 13;
  *code = retCode;
  if(len > 120)
    len = 120;
  if(payloadLen < (13+len))
    return;
  strncpy(errMess, (char*)payload + 13, len);
  errMess[len] = 0;
}

int getOracleUser(char *user, u_char *payload, int payloadLen)
{
  int i, flag;
  char *p, *p2, tmp[32];

  if(payloadLen <= 58)
    return 0;
  p = (char*)payload + 58;
  p2 = strstr(p, "USER=");
  if(p2 == 0)
    return 0;
  p2 += 5;
  tmp[0] = 0;
  flag = 0;
  for(i = 0; i < 31; i++){
    if(p2[i] == ')'){
      flag = 1;
      break;
    }
    tmp[i] = p2[i];
  }
  if(flag){
    tmp[i] = 0;
    strcpy(user, tmp);
  }
  return 1;
}

int getSqlServerUser(char *user, char *dbname, u_char *payload, int payloadLen)
{
  return 0;
}

