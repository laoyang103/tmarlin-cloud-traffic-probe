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
#include "cJSON.h"
#include "disp-process.h"
#include "util.h"

int getIntValue(cJSON *pRoot, const char *str);
int getUIntIPValue(cJSON *pRoot, const char *str);
int getIntRatioValue(cJSON *pRoot, const char *str1, const char *str2);
float getFloatValue(cJSON *pRoot, const char *str);
void getCommValue(cJSON *pRoot, CommValueT *pCommValue);
void getCommValue6(cJSON *pRoot, CommValue6T *pCommValue);
void getBssValue(int type, cJSON *pRoot, BssValueT *pBssValue);
int checkCommValue(CommValueT *pValue);
void getJsonStrTime(cJSON *pRoot, const char *str, char *dst);

extern DispReadOnlyGlobalT dispReadOnlyGlobal;
extern DispGlobalValueT dispGlobalValue;

int analyzeJson(char *str) // Get all information of one session from a json string
{
  int type;
  time_t tt;
  CommValueT commValue;
  CommValue6T commValue6;
  BssValueT bssValue;
  char buf[1024];
  cJSON *pRoot, *pItem;

  pRoot = cJSON_Parse(str);
  if(pRoot == 0)
    return -1;
  pItem = cJSON_GetObjectItem(pRoot, "type");
  if(pItem == 0)
    return -1;
  type = atoi(pItem->valuestring);
  if((type != COMM_TYPE_COMM) && (type != COMM_TYPE_COMMV6)){
    pItem = cJSON_GetObjectItem(pRoot, "begintime");
    strcpy(buf, pItem->valuestring);
    tt = atoll(buf);
    if(tt > dispReadOnlyGlobal.tend)
      return 0;
    pItem = cJSON_GetObjectItem(pRoot, "endtime");
    strcpy(buf, pItem->valuestring);
    tt = atoll(buf);
    if(tt < dispReadOnlyGlobal.tstart)
      return 0;
    memset(&bssValue, 0x00, sizeof(BssValueT));
#ifdef PROCESS_FLOW
    pItem = cJSON_GetObjectItem(pRoot, "process");
    if(pItem != 0){
      strcpy(bssValue.process, pItem->valuestring);
    }
#endif
    getBssValue(type, pRoot, &bssValue);
    cJSON_Delete(pRoot);
    processBssValue(&bssValue); // Display business session data
    return 0;
  }
  pItem = cJSON_GetObjectItem(pRoot, "time");
  strcpy(buf, pItem->valuestring);
  tt = atoll(buf);
  if(tt < dispReadOnlyGlobal.tstart)
    return 0;
  if(tt > dispReadOnlyGlobal.tend)
    return 0;
  if(type == COMM_TYPE_COMMV6){
    memset(&commValue6, 0x00, sizeof(CommValue6T));
    commValue6.time = tt;
    commValue6.sec = 10;
#ifdef PROCESS_FLOW
    pItem = cJSON_GetObjectItem(pRoot, "process");
    if(pItem != 0){
      strcpy(commValue.process, pItem->valuestring);
    }
#endif
    getCommValue6(pRoot, &commValue6);
    cJSON_Delete(pRoot);
    processValue6(&commValue6);
    return 0;
  }
  memset(&commValue, 0x00, sizeof(CommValueT));
  commValue.time = tt;
  commValue.sec = 10;
#ifdef PROCESS_FLOW
  pItem = cJSON_GetObjectItem(pRoot, "process");
  if(pItem != 0){
    strcpy(commValue.process, pItem->valuestring);
  }
#endif
  getCommValue(pRoot, &commValue);
  cJSON_Delete(pRoot);
  if(checkCommValue(&commValue) == 0)
    return 0;
  processValue(&commValue); // Put the data into the container
  return 0;
}

void getCommValue(cJSON *pRoot, CommValueT *pCommValue)
{
  pCommValue->sport = getIntValue(pRoot, "sport");
  pCommValue->dport = getIntValue(pRoot, "dport");
  pCommValue->src = getUIntIPValue(pRoot, "src");
  pCommValue->dst = getUIntIPValue(pRoot, "dst");
  pCommValue->proto = getIntValue(pRoot, "proto");
  pCommValue->bytes = getIntValue(pRoot, "srcBytes");
  pCommValue->bytes += getIntValue(pRoot, "dstBytes");
  pCommValue->pkt = getIntValue(pRoot, "srcPkts");
  pCommValue->pkt += getIntValue(pRoot, "dstPkts");
  pCommValue->lose = getIntRatioValue(pRoot, "srcPkts", "srcLossRatio");
  pCommValue->lose += getIntRatioValue(pRoot, "dstPkts", "dstLossRatio");
  pCommValue->avgLen = getIntValue(pRoot, "avgPktLen");
  pCommValue->tiny = getIntValue(pRoot, "srcTinyPkts");
  pCommValue->tiny += getIntValue(pRoot, "dstTinyPkts");
  pCommValue->fin = getIntValue(pRoot, "srcFinPkts");
  pCommValue->fin += getIntValue(pRoot, "dstFinPkts");
  pCommValue->rst = getIntValue(pRoot, "srcRstPkts");
  pCommValue->rst += getIntValue(pRoot, "dstRstPkts");
  pCommValue->largePkt = getIntValue(pRoot, "largePkts");
  pCommValue->zeroWin = getIntValue(pRoot, "srcZeroWinPkts");
  pCommValue->zeroWin += getIntValue(pRoot, "dstZeroWinPkts");
  pCommValue->syn = getIntValue(pRoot, "srcSynPkts");
  pCommValue->syn += getIntValue(pRoot, "dstSynPkts");
  pCommValue->rtt = getFloatValue(pRoot, "srcNetDelay");
  pCommValue->rtt += getFloatValue(pRoot, "dstNetDelay");
  pCommValue->synRtt = getFloatValue(pRoot, "srcHandDelay");
  pCommValue->synRtt += getFloatValue(pRoot, "dstHandDelay");
  pCommValue->resp = getFloatValue(pRoot, "responseDelay");
  pCommValue->load = getFloatValue(pRoot, "loadTransDelay");
#ifdef PROCESS_FLOW
  pCommValue->mem = getIntValue(pRoot, "mem");
  pCommValue->cpu = getFloatValue(pRoot, "cpu");
#endif
}

void getCommValue6(cJSON *pRoot, CommValue6T *pCommValue)
{
  cJSON *pItem;
  char buf[1024];

  pCommValue->sport = getIntValue(pRoot, "sport");
  pCommValue->dport = getIntValue(pRoot, "dport");
  pItem = cJSON_GetObjectItem(pRoot, "src");
  if(pItem != 0){
    strcpy(buf, pItem->valuestring);
    getUbyteIP6(buf, pCommValue->src);
  }
  pItem = cJSON_GetObjectItem(pRoot, "dst");
  if(pItem != 0){
    strcpy(buf, pItem->valuestring);
    getUbyteIP6(buf, pCommValue->dst);
  }
  pCommValue->proto = getIntValue(pRoot, "proto");
  pCommValue->bytes = getIntValue(pRoot, "srcBytes");
  pCommValue->bytes += getIntValue(pRoot, "dstBytes");
  pCommValue->pkt = getIntValue(pRoot, "srcPkts");
  pCommValue->pkt += getIntValue(pRoot, "dstPkts");
  pCommValue->lose = getIntRatioValue(pRoot, "srcPkts", "srcLossRatio");
  pCommValue->lose += getIntRatioValue(pRoot, "dstPkts", "dstLossRatio");
  pCommValue->avgLen = getIntValue(pRoot, "avgPktLen");
  pCommValue->tiny = getIntValue(pRoot, "srcTinyPkts");
  pCommValue->tiny += getIntValue(pRoot, "dstTinyPkts");
  pCommValue->fin = getIntValue(pRoot, "srcFinPkts");
  pCommValue->fin += getIntValue(pRoot, "dstFinPkts");
  pCommValue->rst = getIntValue(pRoot, "srcRstPkts");
  pCommValue->rst += getIntValue(pRoot, "dstRstPkts");
  pCommValue->largePkt = getIntValue(pRoot, "largePkts");
  pCommValue->zeroWin = getIntValue(pRoot, "srcZeroWinPkts");
  pCommValue->zeroWin += getIntValue(pRoot, "dstZeroWinPkts");
  pCommValue->syn = getIntValue(pRoot, "srcSynPkts");
  pCommValue->syn += getIntValue(pRoot, "dstSynPkts");
  pCommValue->rtt = getFloatValue(pRoot, "srcNetDelay");
  pCommValue->rtt += getFloatValue(pRoot, "dstNetDelay");
  pCommValue->synRtt = getFloatValue(pRoot, "srcHandDelay");
  pCommValue->synRtt += getFloatValue(pRoot, "dstHandDelay");
  pCommValue->resp = getFloatValue(pRoot, "responseDelay");
  pCommValue->load = getFloatValue(pRoot, "loadTransDelay");
#ifdef PROCESS_FLOW
  pCommValue->mem = getIntValue(pRoot, "mem");
  pCommValue->cpu = getFloatValue(pRoot, "cpu");
#endif
}

void getBssValue(int type, cJSON *pRoot, BssValueT *pBssValue)
{
  cJSON *pItem;

#ifdef PROCESS_FLOW
  pBssValue->mem = getIntValue(pRoot, "mem");
  pBssValue->cpu = getFloatValue(pRoot, "cpu");
#endif
  pBssValue->type = type;
  pBssValue->sport = getIntValue(pRoot, "sport");
  pBssValue->dport = getIntValue(pRoot, "dport");
  pBssValue->src = getUIntIPValue(pRoot, "src");
  pBssValue->dst = getUIntIPValue(pRoot, "dst");
  pBssValue->proto = 6;
  pBssValue->bytes = getIntValue(pRoot, "bytes");
  pBssValue->retcode = getIntValue(pRoot, "retcode");
  pBssValue->response = getIntValue(pRoot, "response");
  pBssValue->pageload = getIntValue(pRoot, "pageload");
  getJsonStrTime(pRoot, "begintime", pBssValue->beginTime);
  getJsonStrTime(pRoot, "endtime", pBssValue->endTime);
  if(type == COMM_TYPE_HTTP){
    pBssValue->pageload = getIntValue(pRoot, "pageload");
    pItem = cJSON_GetObjectItem(pRoot, "url");
    if(pItem != 0)
      strncpy(pBssValue->url, pItem->valuestring, 250);
    pItem = cJSON_GetObjectItem(pRoot, "domain");
    if(pItem != 0)
      strncpy(pBssValue->domain, pItem->valuestring, 30);
    pItem = cJSON_GetObjectItem(pRoot, "contentType");
    if(pItem != 0)
      strncpy(pBssValue->contentType, pItem->valuestring, 30);
    pItem = cJSON_GetObjectItem(pRoot, "agent");
    if(pItem != 0)
      strncpy(pBssValue->agent, pItem->valuestring, 30);
    pItem = cJSON_GetObjectItem(pRoot, "method");
    if(pItem != 0)
      strncpy(pBssValue->method, pItem->valuestring, 6);
    return;
  }
  pItem = cJSON_GetObjectItem(pRoot, "sql");
  if(pItem != 0)
    strncpy(pBssValue->url, pItem->valuestring, 250);
  pItem = cJSON_GetObjectItem(pRoot, "err");
  if(pItem != 0)
    strncpy(pBssValue->domain, pItem->valuestring, 30);
  pItem = cJSON_GetObjectItem(pRoot, "user");
  if(pItem != 0)
    strncpy(pBssValue->contentType, pItem->valuestring, 250);
  pItem = cJSON_GetObjectItem(pRoot, "dbname");
  if(pItem != 0)
    strncpy(pBssValue->agent, pItem->valuestring, 250);
}

int checkCommValue(CommValueT *pValue)  // Remove invalid data, by command line arguments
{
  int i, cnt;
  FilterInfoT *pFilter;

  cnt = dispReadOnlyGlobal.cntFilter;
  if(cnt <= 0)
    return 1;
  for(i = 0; i < cnt; i++){
    pFilter = dispReadOnlyGlobal.filters + i;
    if((pValue->src >= pFilter->addressLow) && (pValue->src <= pFilter->addressHigh)){
      if(pFilter->port == 0)
        return 1;
      if(pFilter->port == pValue->sport)
        return 1;
    }
    if((pValue->dst >= pFilter->addressLow) && (pValue->dst <= pFilter->addressHigh)){
      if(pFilter->port == 0)
        return 1;
      if(pFilter->port == pValue->dport)
        return 1;
    }
    if((pFilter->addressLow == 0) || (pFilter->addressHigh == 0)){
      if(pFilter->port == pValue->dport)
        return 1;
      if(pFilter->port == pValue->sport)
        return 1;
    }
  }
  return 0;
}

int getIntValue(cJSON *pRoot, const char *str)
{
  cJSON *pItem;
  char buf[1024];

  pItem = cJSON_GetObjectItem(pRoot, str);
  if(pItem == 0)
    return 0;
  strcpy(buf, pItem->valuestring);
  return atoi(buf);
}

int getUIntIPValue(cJSON *pRoot, const char *str)
{
  cJSON *pItem;
  char buf[1024];
  u_int32_t uv;

  pItem = cJSON_GetObjectItem(pRoot, str);
  if(pItem == 0)
    return 0;
  strcpy(buf, pItem->valuestring);
  uv = getDispIPFromStr(buf);
  return uv;
}

int getIntRatioValue(cJSON *pRoot, const char *str1, const char *str2)
{
  cJSON *pItem;
  char buf[1024];
  double dv;
  int v;

  pItem = cJSON_GetObjectItem(pRoot, str1);
  if(pItem == 0)
    return 0;
  strcpy(buf, pItem->valuestring);
  v = atoi(buf);
  pItem = cJSON_GetObjectItem(pRoot, str2);
  if(pItem == 0)
    return 0;
  strcpy(buf, pItem->valuestring);
  dv = atof(buf);
  dv = dv * v;
  return (int)dv;
}

float getFloatValue(cJSON *pRoot, const char *str)
{
  cJSON *pItem;
  char buf[1024];

  pItem = cJSON_GetObjectItem(pRoot, str);
  if(pItem == 0)
    return 0.0;
  strcpy(buf, pItem->valuestring);
  return atof(buf);
}

void getJsonStrTime(cJSON *pRoot, const char *str, char *dst)
{
  cJSON *pItem;
  time_t tt;
  char *p;
  int i, len;
  char buf[1024];

  pItem = cJSON_GetObjectItem(pRoot, str);
  if(pItem == 0)
    return;
  strcpy(buf, pItem->valuestring);
  len = strlen(buf);
  p = 0;
  for(i = 0; i < len; i++){
    if(buf[i] == '.'){
      p = buf + i;
      buf[i] = 0;
      break;
    }
  }
  tt = atol(buf);
  getStrTime(tt, dst);
  if(p != 0){
    *p = '.';
    p[4] = 0;
    strcat(dst, p);
  }
}
