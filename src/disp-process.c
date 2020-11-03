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
#include "util.h"

extern DispReadOnlyGlobalT dispReadOnlyGlobal;
extern DispGlobalValueT dispGlobalValue;

int fieldLen[3];
char fieldMinus[3][128], linePrefix[128];
char fieldName[3][128];

void printGrid2();
void printName();

void processValue(CommValueT *pValue)  // Put the data into the container
{
  int i, cnt, find, ind;
  CommValueT *pCommValue, *ptmp;

  cnt = dispGlobalValue.cntValue;
  pCommValue = dispGlobalValue.pCommValue;
  if(cnt == 0){
    memcpy(pCommValue, pValue, sizeof(CommValueT));
    dispGlobalValue.cntValue = 1;
    return;
  }
  find = 0;
  for(i = 0; i < cnt; i++){  // Check the same session data
    ptmp = pCommValue + i;
    if(pValue->proto != ptmp->proto)
      continue;
    if((pValue->src == ptmp->src) && (pValue->sport == ptmp->sport) && (pValue->dst == ptmp->dst) && (pValue->dport == ptmp->dport))
      find = 1;
    if((pValue->src == ptmp->dst) && (pValue->sport == ptmp->dport) && (pValue->dst == ptmp->src) && (pValue->dport == ptmp->sport))
      find = 1;
    if(find){
      ind = i;
      break;
    }
  }
  if(!find){  // New session data
    if(dispGlobalValue.cntValue >= MAX_COMM_VALUE)
      return;
    ind = cnt;
    dispGlobalValue.cntValue++;
    memcpy(pCommValue + ind, pValue, sizeof(CommValueT));
    return;
  }
  ptmp = pCommValue + ind;  // Merge session data
  ptmp->bytes += pValue->bytes;
  ptmp->pkt += pValue->pkt;
  ptmp->lose += pValue->lose;
  ptmp->tiny += pValue->tiny;
  ptmp->avgLen = (pValue->avgLen*pValue->pkt + ptmp->avgLen*ptmp->pkt) / (pValue->pkt + ptmp->pkt);
  ptmp->fin += pValue->fin;
  ptmp->rst += pValue->rst;
  ptmp->largePkt += pValue->largePkt;
  ptmp->zeroWin += pValue->zeroWin;
  ptmp->syn += pValue->syn;
  ptmp->rtt = avgFloatValue(ptmp->rtt, pValue->rtt);
  ptmp->synRtt = avgFloatValue(ptmp->synRtt, pValue->synRtt);
  ptmp->resp = avgFloatValue(ptmp->resp, pValue->resp);
  ptmp->load = avgFloatValue(ptmp->load, pValue->load);
  if(ptmp->time > pValue->time){
    ptmp->sec = ptmp->time - pValue->time + 10;
    ptmp->time = pValue->time;
  }else{
    ptmp->sec = pValue->time - ptmp->time + 10;
  }
}

void processValue6(CommValue6T *pValue)  // Put the data into the container of IPV6
{
  int i, cnt, find, ind;
  CommValue6T *pCommValue, *ptmp;

  cnt = dispGlobalValue.cntValue6;
  pCommValue = dispGlobalValue.pCommValue6;
  if(cnt == 0){
    memcpy(pCommValue, pValue, sizeof(CommValue6T));
    dispGlobalValue.cntValue6 = 1;
    return;
  }
  find = 0;
  for(i = 0; i < cnt; i++){
    ptmp = pCommValue + i;
    if(pValue->proto != ptmp->proto)
      continue;
    if(!memcmp(pValue->src, ptmp->src, 16) && (pValue->sport == ptmp->sport) && !memcmp(pValue->dst, ptmp->dst, 16) && (pValue->dport == ptmp->dport))
      find = 1;
    if(!memcmp(pValue->src, ptmp->dst, 16) && (pValue->sport == ptmp->dport) && !memcmp(pValue->dst, ptmp->src, 16) && (pValue->dport == ptmp->sport))
      find = 1;
    if(find){
      ind = i;
      break;
    }
  }
  if(!find){
    if(dispGlobalValue.cntValue6 >= MAX_COMM_VALUE)
      return;
    ind = cnt;
    dispGlobalValue.cntValue6++;
    memcpy(pCommValue + ind, pValue, sizeof(CommValue6T));
    return;
  }
  ptmp = pCommValue + ind;
  ptmp->bytes += pValue->bytes;
  ptmp->pkt += pValue->pkt;
  ptmp->lose += pValue->lose;
  ptmp->tiny += pValue->tiny;
  ptmp->avgLen = (pValue->avgLen*pValue->pkt + ptmp->avgLen*ptmp->pkt) / (pValue->pkt + ptmp->pkt);
  ptmp->fin += pValue->fin;
  ptmp->rst += pValue->rst;
  ptmp->largePkt += pValue->largePkt;
  ptmp->zeroWin += pValue->zeroWin;
  ptmp->syn += pValue->syn;
  ptmp->rtt = avgFloatValue(ptmp->rtt, pValue->rtt);
  ptmp->synRtt = avgFloatValue(ptmp->synRtt, pValue->synRtt);
  ptmp->resp = avgFloatValue(ptmp->resp, pValue->resp);
  ptmp->load = avgFloatValue(ptmp->load, pValue->load);
  if(ptmp->time > pValue->time){
    ptmp->sec = ptmp->time - pValue->time + 10;
    ptmp->time = pValue->time;
  }else{
    ptmp->sec = pValue->time - ptmp->time + 10;
  }
}

int matchStr(const char *str)
{
  char *p, tmp[1024];

  strcpy(tmp, dispReadOnlyGlobal.content);
  p = strstr(str, tmp);
  if(p != 0)
    return 1;
  toLowerCase(tmp);
  p = strstr(str, tmp);
  if(p != 0)
    return 1;
  toUpperCase(tmp);
  p = strstr(str, tmp);
  if(p != 0)
    return 1;
  return 0;
}

void processBssValue(BssValueT *pBssValue)
{
  int flag;

  if(dispGlobalValue.cntBssValue >= MAX_COMM_VALUE)
    return;
  flag = 1;
  if(dispReadOnlyGlobal.isContent){  // Filter by keywords string
    flag = matchStr(pBssValue->url);
    if(flag == 0){
      if(pBssValue->type == COMM_TYPE_HTTP)
        flag = matchStr(pBssValue->domain);
    }
  }
  if(flag == 0)
    return;
  memcpy(dispGlobalValue.pBssValue + dispGlobalValue.cntBssValue, pBssValue, sizeof(BssValueT));
  dispGlobalValue.cntBssValue++;
}

void printHead()  // Print grid head
{
  int i, j;
  char buf[1024];

  memset(fieldMinus[0], 0x00, 128);
  memset(fieldMinus[1], 0x00, 128);
  memset(fieldMinus[2], 0x00, 128);
  memset(buf, 0x00, 1024);
  for (i = 0; i < 3; i++) {  // Fill the row string in the grid
    fieldLen[i] = strlen(fieldName[i]);
    fieldMinus[i][0] = '+';
    for(j = 0; j < fieldLen[i]; j++)
      fieldMinus[i][j+1] = '-';
    fieldMinus[i][fieldLen[i] + 1] = 0;
  }
  printGrid2();
  printName();
  printGrid2();
}

void displayValue() // Print grid information
{
  int i, j, cnt;
  CommValueT *pCommValue;
  CommValue6T *pCommValue6;
  char *p, buf[1024], tmp[1024], tmp1[256], tmp2[256];

  strcpy(fieldName[0], "Time                     ");
  strcpy(fieldName[1], "IP                                              ");
  strcpy(fieldName[2], "KPI                                                                                                  ");
  printHead();



  cnt = dispGlobalValue.cntValue;
  for(i = 0; i < cnt; i++){
    pCommValue = dispGlobalValue.pCommValue + i;

    buf[0] = '|';  // Print the first row in the first column, start time
    buf[1] = ' ';
    buf[2] = ' ';
    buf[3] = 0;
    getDispStrTime(pCommValue->time, tmp1);
    strcat(buf, tmp1);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';  // Print the first row in the second column, source IP:PORT
    p = p + j + 1;
    p[0] = ' ';
    p[1] = ' ';
    p[2] = 0;
    getStrIP(pCommValue->src, tmp1);
    sprintf(tmp, "%s:%d", tmp1, pCommValue->sport);
    strcat(p, tmp);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';  // Print the third column, KPI
    p[j+1] = 0;
    p = p + j + 1;
    sprintf(tmp1, "proto:tcp");
    if(pCommValue->proto == 17)
      sprintf(tmp1, "proto:udp");
    if(pCommValue->proto == 1)
      sprintf(tmp1, "proto:icmp");
    getDispTraffic(pCommValue->bytes, tmp2);
    sprintf(tmp, "%s, traffic:%s, ", tmp1, tmp2);
    getDispPkts(pCommValue->pkt, tmp1);
    sprintf(tmp2, "pkt:%s, ", tmp1);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue->lose, tmp1);
    sprintf(tmp2, "loss:%s, ", tmp1);
    strcat(tmp, tmp2);
    sprintf(tmp2, "avgPktLen:%d, ", pCommValue->avgLen);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue->syn, tmp1);
    sprintf(tmp2, "synPkts:%s, ", tmp1);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue->tiny, tmp1);
    sprintf(tmp2, "tinyPkts:%s, ", tmp1);
    strcat(tmp, tmp2);
    strcat(p, tmp);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    buf[0] = '|';  // Print the second row in the first column, end time
    buf[1] = ' ';
    buf[2] = '-';
    buf[3] = '-';
    buf[4] = ' ';
    buf[5] = 0;
    getDispStrTime(pCommValue->time+pCommValue->sec, tmp2);
    strcat(buf, tmp2);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';  // Print the second row in the second column, destination IP:PORT
    p[j+1] = 0;
    p = p + j + 1;
    p[0] = ' ';
    p[1] = '-';
    p[2] = '-';
    p[3] = ' ';
    p[4] = 0;
    getStrIP(pCommValue->dst, tmp1);
    sprintf(tmp2, "%s:%d", tmp1, pCommValue->dport);
    strcat(p, tmp2);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|'; // Print the third column in second row, KPI
    p[j+1] = 0;
    p = p + j + 1;
    getDispPkts(pCommValue->fin, tmp1);
    sprintf(tmp2, "finPkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue->rst, tmp1);
    sprintf(tmp2, "rstPkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue->largePkt, tmp1);
    sprintf(tmp2, "largePkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue->zeroWin, tmp1);
    sprintf(tmp2, "zeroWinPkts:%s, ", tmp1);
    strcat(p, tmp2);
    sprintf(tmp1, "rttDelay:%.2f, ", pCommValue->rtt);
    strcat(p, tmp1);
    sprintf(tmp1, "synDelay:%.2f, ", pCommValue->synRtt);
    strcat(p, tmp1);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    buf[0] = '|';  // In third row, the first and second columns have no data
    p = buf + 1;
    for(j = 0; j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    for(j = 0; j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    sprintf(tmp1, "respDelay:%.2f, ", pCommValue->resp);
    strcat(p, tmp1);
    sprintf(tmp1, "loadDelay:%.2f", pCommValue->load);
#ifdef PROCESS_FLOW
    sprintf(tmp1, "loadDelay:%.2f,", pCommValue->load);
#endif
    strcat(p, tmp1);
#ifdef PROCESS_FLOW
    sprintf(tmp1, "process:%s", pCommValue->process);
    strcat(p, tmp1);
    sprintf(tmp1, ", cpu:%.2f", pCommValue->cpu);
    strcat(p, tmp1);
    sprintf(tmp1, ", mem:%d KB", pCommValue->mem);
    strcat(p, tmp1);
#endif
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    printGrid2();
  }



  cnt = dispGlobalValue.cntValue6;
  for(i = 0; i < cnt; i++){
    pCommValue6 = dispGlobalValue.pCommValue6 + i;

    buf[0] = '|';
    buf[1] = ' ';
    buf[2] = ' ';
    buf[3] = 0;
    getDispStrTime(pCommValue6->time, tmp1);
    strcat(buf, tmp1);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p = p + j + 1;
    p[0] = ' ';
    p[1] = ' ';
    p[2] = 0;
    getIPV6Str(pCommValue6->src, tmp1);
    sprintf(tmp, "%s-%d", tmp1, pCommValue6->sport);
    strcat(p, tmp);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    sprintf(tmp1, "proto:tcp");
    if(pCommValue6->proto == 17)
      sprintf(tmp1, "proto:udp");
    if(pCommValue6->proto == 1)
      sprintf(tmp1, "proto:icmp");
    getDispTraffic(pCommValue6->bytes, tmp2);
    sprintf(tmp, "%s, traffic:%s, ", tmp1, tmp2);
    getDispPkts(pCommValue6->pkt, tmp1);
    sprintf(tmp2, "pkt:%s, ", tmp1);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue6->lose, tmp1);
    sprintf(tmp2, "loss:%s, ", tmp1);
    strcat(tmp, tmp2);
    sprintf(tmp2, "avgPktLen:%d, ", pCommValue6->avgLen);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue6->syn, tmp1);
    sprintf(tmp2, "synPkts:%s, ", tmp1);
    strcat(tmp, tmp2);
    getDispPkts(pCommValue6->tiny, tmp1);
    sprintf(tmp2, "tinyPkts:%s, ", tmp1);
    strcat(tmp, tmp2);
    strcat(p, tmp);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    buf[0] = '|';
    buf[1] = ' ';
    buf[2] = '-';
    buf[3] = '-';
    buf[4] = ' ';
    buf[5] = 0;
    getDispStrTime(pCommValue6->time+pCommValue6->sec, tmp2);
    strcat(buf, tmp2);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    p[0] = ' ';
    p[1] = '-';
    p[2] = '-';
    p[3] = ' ';
    p[4] = 0;
    getIPV6Str(pCommValue6->dst, tmp1);
    sprintf(tmp2, "%s-%d", tmp1, pCommValue6->dport);
    strcat(p, tmp2);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    getDispPkts(pCommValue6->fin, tmp1);
    sprintf(tmp2, "finPkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue6->rst, tmp1);
    sprintf(tmp2, "rstPkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue6->largePkt, tmp1);
    sprintf(tmp2, "largePkts:%s, ", tmp1);
    strcat(p, tmp2);
    getDispPkts(pCommValue6->zeroWin, tmp1);
    sprintf(tmp2, "zeroWinPkts:%s, ", tmp1);
    strcat(p, tmp2);
    sprintf(tmp1, "rttDelay:%.2f, ", pCommValue6->rtt);
    strcat(p, tmp1);
    sprintf(tmp1, "synDelay:%.2f, ", pCommValue6->synRtt);
    strcat(p, tmp1);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    buf[0] = '|';
    p = buf + 1;
    for(j = 0; j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    for(j = 0; j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    sprintf(tmp1, "respDelay:%.2f, ", pCommValue6->resp);
    strcat(p, tmp1);
    sprintf(tmp1, "loadDelay:%.2f", pCommValue6->load);
    strcat(p, tmp1);
#ifdef PROCESS_FLOW
    sprintf(tmp1, ", process:%s", pCommValue6->process);
    strcat(p, tmp1);
    sprintf(tmp1, ", cpu:%.2f", pCommValue6->cpu);
    strcat(p, tmp1);
    sprintf(tmp1, ", mem:%d KB", pCommValue6->mem);
    strcat(p, tmp1);
#endif
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    printGrid2();  // Print rows in grid
  }
}

void printGrid2()
{
  int i;
  char buf[1024];

  buf[0] = 0;
  for(i = 0; i < 3; i++){
    strcat(buf, fieldMinus[i]);
  }
  strcat(buf, "+");
  printf("%s\n", buf);
}

void printName()
{
  int i, len;
  char buf[1024], *p;

  buf[0] = '|';
  buf[1] = 0;
  for(i = 0; i < 3; i++){
    strcat(buf, fieldName[i]);
    strcat(buf, "|");
  }
  printf("%s\n", buf);
  memset(linePrefix, 0x00, 128);
  linePrefix[0] = '|';
  p = linePrefix + 1;
  len = strlen(fieldName[0]);
  for(i = 0; i < len; i++){
    p[i] = ' ';
  }
  p = linePrefix + len + 1;
  *p = '|';
  p++;
  len = strlen(fieldName[1]);
  for(i = 0; i < len; i++)
    p[i] = ' ';
  p[len] = '|';
}

void displayBssValue()
{
  int i, j, cnt;
  BssValueT *pBssValue;
  char *p, buf[1024], tmp[1024], tmp1[256], tmp2[256];

  if(dispGlobalValue.cntBssValue == 0)
    return;
  printf("\n");
  strcpy(fieldName[2], "INFO                                                                                                                   ");
  printHead();
  cnt = dispGlobalValue.cntBssValue;
  for(i = 0; i < cnt; i++){
    pBssValue = dispGlobalValue.pBssValue + i;

    buf[0] = '|';
    buf[1] = ' ';
    buf[2] = ' ';
    buf[3] = 0;
    strcat(buf, pBssValue->beginTime);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p = p + j + 1;
    p[0] = ' ';
    p[1] = ' ';
    p[2] = 0;
    getStrIP(pBssValue->src, tmp1);
    sprintf(tmp, "%s:%d", tmp1, pBssValue->sport);
    strcat(p, tmp);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    pBssValue->url[90] = 0;
    if(pBssValue->type == COMM_TYPE_HTTP){
      sprintf(tmp1, "url:%s", pBssValue->url);
      strcat(p, tmp1);
      sprintf(tmp1, ", method:%s,", pBssValue->method);
      strcat(p, tmp1);
    }else{
      sprintf(tmp1, "sql:%s", pBssValue->url);
      strcat(p, tmp1);
      sprintf(tmp1, ", user:%s,", pBssValue->contentType);
      strcat(p, tmp1);
    }
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

    buf[0] = '|';
    buf[1] = ' ';
    buf[2] = '-';
    buf[3] = '-';
    buf[4] = ' ';
    buf[5] = 0;
    strcat(buf, pBssValue->endTime);
    p = buf + 1;
    for(j = strlen(p); j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    p[0] = ' ';
    p[1] = '-';
    p[2] = '-';
    p[3] = ' ';
    p[4] = 0;
    getStrIP(pBssValue->dst, tmp1);
    sprintf(tmp2, "%s:%d", tmp1, pBssValue->dport);
    strcat(p, tmp2);
    for(j = strlen(p); j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    pBssValue->domain[18] = 0;
    pBssValue->agent[18] = 0;
    if(pBssValue->type == COMM_TYPE_HTTP){
      sprintf(tmp1, "domain:%s", pBssValue->domain);
      strcat(p, tmp1);
      sprintf(tmp1, ", agent:%s", pBssValue->agent);
      strcat(p, tmp1);
      sprintf(tmp1, ", bytes:%d", pBssValue->bytes);
      strcat(p, tmp1);
    }else{
      sprintf(tmp1, "error:%s", pBssValue->domain);
      strcat(p, tmp1);
      sprintf(tmp1, "user:%s", pBssValue->contentType);
      strcat(p, tmp1);
      sprintf(tmp1, "dbname:%s", pBssValue->agent);
      strcat(p, tmp1);
    }
    sprintf(tmp1, ", retcode:%d", pBssValue->retcode);
    strcat(p, tmp1);
    sprintf(tmp1, ", response:%.2f", (float)(pBssValue->response) / 1000);
    strcat(p, tmp1);
    sprintf(tmp1, ", pageload:%.2f", (float)(pBssValue->pageload) / 1000);
#ifdef PROCESS_FLOW
    sprintf(tmp1, ", pageload:%.2f,", (float)(pBssValue->pageload) / 1000);
#endif
    strcat(p, tmp1);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);

#ifdef PROCESS_FLOW
    buf[0] = '|';
    p = buf + 1;
    for(j = 0; j < fieldLen[0]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    for(j = 0; j < fieldLen[1]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    p = p + j + 1;
    sprintf(tmp1, "process:%s", pBssValue->process);
    strcat(p, tmp1);
    sprintf(tmp1, ", cpu:%.2f", pBssValue->cpu);
    strcat(p, tmp1);
    sprintf(tmp1, ", mem:%d KB", pBssValue->mem);
    strcat(p, tmp1);
    for(j = strlen(p); j < fieldLen[2]; j++)
      p[j] = ' ';
    p[j] = '|';
    p[j+1] = 0;
    printf("%s\n", buf);
#endif

    printGrid2();
  }
}
