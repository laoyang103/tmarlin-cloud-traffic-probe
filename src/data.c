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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "log.h"
#include "util.h"
#include "store.h"
#ifdef PROCESS_FLOW
#include "inode.h"
#endif

#define MAX_COMM_SIZE          65536

typedef struct grehdr {
  uint16_t flags;
  uint16_t protocol;
  uint32_t keybit;
} grehdr_t;

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
int expSockfd, expPktSockfd;

void makeJsonStr(CommMsgT *pCommMsg, char *str);
void makeJsonStr6(CommMsg6T *pCommMsg, char *str);
void makeEndJsonStr(char *str, time_t stamp);
int makeBusinessJsonStr(NetSessionT *pNetSession, char *str);

int initExpSock()  // init json export socket
{
  socklen_t slen;

  slen = sizeof(struct sockaddr_in);
  expSockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (expSockfd < 0) return -1;
  if (connect(expSockfd, (struct sockaddr*)&readOnlyGlobal.expAddress, slen) < 0){
    writeLog(PROBE_LOG_ERROR, "connect export server %s:%d failed: %s\n", 
        readOnlyGlobal.configInfo.expDomain, readOnlyGlobal.configInfo.expPort, strerror(errno));
    close(expSockfd);
    return -1;
  }
  return 0;
}

int initPacketSock()  // init packet export socket
{
  expPktSockfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
  if (expPktSockfd < 0) return -1;

  readOnlyGlobal.expPktAddress.sin_port = 0;
  return 0;
}

int exportPacketData(const struct pcap_pkthdr *h, const u_char *sp) //send packet data
{
  int len, v, n;
  grehdr_t hdr;
  u_char ubuf[65536];

  if(!readOnlyGlobal.isPktExp)
    return 0;
  hdr.flags = htons(0x2000);
  hdr.protocol = htons(0x6558);
  v = readOnlyGlobal.mac[4]*256 + readOnlyGlobal.mac[5];
  hdr.keybit = htonl(v);
  len = sizeof(grehdr_t);
  v = h->caplen;
  if(v > 65500)
    v = 65500;
  memcpy(ubuf, &hdr, len);
  memcpy(ubuf + len, sp, v);
  len += v;
  v = sendto(expPktSockfd, (char*)ubuf, len, 0, (struct sockaddr *)&readOnlyGlobal.expPktAddress, sizeof(struct sockaddr));
  if(v < 0){
    n = 3;
    while(n > 0){
      v = sendto(expPktSockfd, (char*)ubuf, len, 0, (struct sockaddr *)&readOnlyGlobal.expPktAddress, sizeof(struct sockaddr));
      n--;
      if(v > 0)
        break;
    }
  }
  return 0;
}

int exportData(CommMsgT *pCommMsg, time_t stamp)   //send json data
{
  int len, v, n;
  char buf[4096];

  if((!readOnlyGlobal.enableJson) && (!readOnlyGlobal.isExp))
    return 0;
  pCommMsg->type = COMM_TYPE_COMM;
  pCommMsg->time = stamp;
  pCommMsg->lid = 0;
  pCommMsg->vid = 0;
  pCommMsg->did = readOnlyGlobal.did;
  makeJsonStr(pCommMsg, buf);
  len = strlen(buf);
  if(readOnlyGlobal.isExp){
    v = sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
    if(v < 0){
      n = 3;
      while(n > 0){
        v = sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
        n--;
        if(v > 0)
          break;
      }
    }
  }
  usleep(10);
  if(readOnlyGlobal.enableJson)
    writeJson(buf, stamp);
  return 0;
}

int exportData6(CommMsg6T *pCommMsg, time_t stamp)
{
  int len, v, n;
  char buf[4096];

  if((!readOnlyGlobal.enableJson) && (!readOnlyGlobal.isExp))
    return 0;
  pCommMsg->type = COMM_TYPE_COMM;
  pCommMsg->time = stamp;
  pCommMsg->lid = 0;
  pCommMsg->vid = 0;
  pCommMsg->did = readOnlyGlobal.did;
  makeJsonStr6(pCommMsg, buf);
  len = strlen(buf);
  if(readOnlyGlobal.isExp){
    v = sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
    if(v < 0){
      n = 3;
      while(n > 0){
        v = sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
        n--;
        if(v > 0)
          break;
      }
    }
  }
  if(readOnlyGlobal.enableJson)
    writeJson(buf, stamp);
  return 0;
}

int exportBusinessData(NetSessionT *pNetSession)
{
  int len;
  char buf[4096];

  if((!readOnlyGlobal.enableJson) && (!readOnlyGlobal.isExp))
    return 0;
  pNetSession->lid = 0;
  pNetSession->vid = 0;
  pNetSession->did = readOnlyGlobal.did;
  if(makeBusinessJsonStr(pNetSession, buf))
    return -1;
  len = strlen(buf);
  if(readOnlyGlobal.isExp)
    sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
  if(readOnlyGlobal.enableJson)
    writeJson(buf, globalValue.currTime);
  return 0;
}

int exportEndData(time_t stamp)
{
  int len;
  char buf[1024];

  globalValue.flushPkts = 1;
  if(readOnlyGlobal.enableJson)
    writeJsonEnd();
  if (!readOnlyGlobal.isExp) return 0;
  makeEndJsonStr(buf, stamp);
  len = strlen(buf);
  len = sendto(expSockfd, buf, len, 0, (struct sockaddr *)&readOnlyGlobal.expAddress, sizeof(struct sockaddr));
  return 0;
}

void makeJsonStr(CommMsgT *pCommMsg, char *str)  // make json string of ip session
{
  float bytes, pkts;
  char s1[32], s2[32], sm1[64], sm2[64], tmp[1024], strTime[256];

  pkts = pCommMsg->rcvdPkts + pCommMsg->sendPkts;
  bytes = pCommMsg->sendBytes + pCommMsg->rcvdBytes;
  getStrTime(pCommMsg->time, strTime);
  sprintf(s1, "%d.%d.%d.%d", pCommMsg->src/256/256/256, pCommMsg->src/256/256%256, pCommMsg->src/256%256, pCommMsg->src%256);
  sprintf(s2, "%d.%d.%d.%d", pCommMsg->dst/256/256/256, pCommMsg->dst/256/256%256, pCommMsg->dst/256%256, pCommMsg->dst%256);
  sprintf(str, "{\"type\":\"%d\",\"time\":\"%ld\",\"strTime\":\"%s\"", COMM_TYPE_COMM, pCommMsg->time, strTime);
#ifdef PROCESS_FLOW
  sprintf(tmp, ",\"process\":\"%s\",\"cpu\":\"%.2f\",\"mem\":\"%d KB\"", pCommMsg->process, pCommMsg->cpu, pCommMsg->mem);
  strcat(str, tmp);
#endif
  getStrMac(pCommMsg->macSrc, sm1);
  getStrMac(pCommMsg->macDst, sm2);
  sprintf(tmp, ",\"srcMac\":\"%s\",\"dstMac\":\"%s\"", sm1, sm2);
  strcat(str, tmp);
  sprintf(tmp, ",\"src\":\"%s\",\"dst\":\"%s\",\"proto\":\"%d\",\"deviceId\":\"%s\",\"did\":\"%d\"", s1, s2, pCommMsg->proto, readOnlyGlobal.devMac, pCommMsg->did);
  strcat(str, tmp);
  sprintf(tmp, ",\"lid\":\"%d\",\"vid\":\"%d\",\"sport\":\"%d\",\"dport\":\"%d\"", pCommMsg->lid, pCommMsg->vid, pCommMsg->sport, pCommMsg->dport);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcBytes\":\"%ld\",\"dstBytes\":\"%ld\",\"srcPkts\":\"%d\"", pCommMsg->sendBytes, pCommMsg->rcvdBytes, pCommMsg->sendPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"dstPkts\":\"%d\"", pCommMsg->rcvdPkts);
  strcat(str, tmp);
  if(pkts > 0){
    sprintf(tmp, ",\"avgPktLen\":\"%.2f\"", ((float)bytes)/pkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"avgPktLen\":\"0.00\"");
  }
  sprintf(tmp, ",\"srcRetransPkts\":\"%d\"", pCommMsg->sendRetransmitPkts);
  strcat(str, tmp);
  if((pCommMsg->sendPkts > 0) && (pCommMsg->sendRetransmitPkts > 0)){
    sprintf(tmp, ",\"srcLossRatio\":\"%.3f\"", (float)pCommMsg->sendRetransmitPkts/(float)pCommMsg->sendPkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcLossRatio\":\"0.00\"");
  }
  sprintf(tmp, ",\"dstRetransPkts\":\"%d\"", pCommMsg->rcvdRetransmitPkts);
  strcat(str, tmp);
  if((pCommMsg->rcvdRetransmitPkts > 0) && (pCommMsg->rcvdPkts > 0)){
    sprintf(tmp, ",\"dstLossRatio\":\"%.3f\"", (float)pCommMsg->rcvdRetransmitPkts/(float)pCommMsg->rcvdPkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstLossRatio\":\"0.00\"");
  }
  sprintf(tmp, ",\"srcZeroWinPkts\":\"%d\",\"dstZeroWinPkts\":\"%d\"", pCommMsg->cntSrcZeroWin, pCommMsg->cntDstZeroWin);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcSynPkts\":\"%d\",\"dstSynPkts\":\"%d\",\"largePkts\":\"%d\"", pCommMsg->sendSynPkts, pCommMsg->rcvdSynPkts, pCommMsg->largePkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcSynAckPkts\":\"%d\",\"dstSynAckPkts\":\"%d\"", pCommMsg->sendSynAckPkts, pCommMsg->rcvdSynAckPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcRstPkts\":\"%d\",\"dstRstPkts\":\"%d\",\"srcFinPkts\":\"%d\"", pCommMsg->sendRstPkts, pCommMsg->rcvdRstPkts, pCommMsg->sendFinPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"dstFinPkts\":\"%d\",\"srcTinyPkts\":\"%d\",\"dstTinyPkts\":\"%d\"", pCommMsg->rcvdFinPkts, pCommMsg->sendTinyPkts, pCommMsg->rcvdTinyPkts);
  strcat(str, tmp);
  if(pCommMsg->cntSrcDelay > 0){
    sprintf(tmp, ",\"srcNetDelay\":\"%.3f\"", (float)pCommMsg->srcDelayUsec/(float)(pCommMsg->cntSrcDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcNetDelay\":\"0.00\"");
  }
  if(pCommMsg->cntDstDelay > 0){
    sprintf(tmp, ",\"dstNetDelay\":\"%.3f\"", (float)pCommMsg->dstDelayUsec/(float)(pCommMsg->cntDstDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstNetDelay\":\"0.00\"");
  }
  if(pCommMsg->srcConDelayUsec > 0){
    sprintf(tmp, ",\"srcHandDelay\":\"%.3f\"", (float)pCommMsg->srcConDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcHandDelay\":\"0.00\"");
  }
  if(pCommMsg->dstConDelayUsec > 0){
    sprintf(tmp, ",\"dstHandDelay\":\"%.3f\"", (float)pCommMsg->dstConDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstHandDelay\":\"0.00\"");
  }
  if(pCommMsg->cntCustomDelay > 0){
    sprintf(tmp, ",\"responseDelay\":\"%.3f\"", (float)pCommMsg->customDelayUsec/(float)(pCommMsg->cntCustomDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"responseDelay\":\"0.00\"");
  }
  if(pCommMsg->cntLoadDelay > 0){
    sprintf(tmp, ",\"loadTransDelay\":\"%.3f\"", (float)pCommMsg->loadDelayUsec/(float)(pCommMsg->cntLoadDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"loadTransDelay\":\"0.00\"");
  }
  if(pCommMsg->srcRetransDelayUsec > 0){
    sprintf(tmp, ",\"srcRetransDelay\":\"%.3f\"", (float)pCommMsg->srcRetransDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcRetransDelay\":\"0.00\"");
  }
  if(pCommMsg->dstRetransDelayUsec > 0){
    sprintf(tmp, ",\"dstRetransDelay\":\"%.3f\"", (float)pCommMsg->dstRetransDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstRetransDelay\":\"0.00\"");
  }
  strcat(str, "}");
}

void makeEndJsonStr(char *str, time_t stamp)
{
  sprintf(str, "{\"type\":\"%d\",\"time\":\"%ld\"}", COMM_TYPE_END, stamp);
}

void delQuota(char *str)
{
  int i, j, len;
  char buf[1024];

  strcpy(buf, str);
  len = strlen(buf);
  j = 0;
  for(i = 0; i < len; i++){
    if(buf[i] == '"')
      continue;
    str[j] = buf[i];
    j++;
  }
  str[j] = 0;
}

int makeBusinessJsonStr(NetSessionT *pNetSession, char *str)  // make business (like http or db) json string of ip session
{
  char s1[128], s2[128], sm1[64], sm2[64], tmp[4096], strTime[256];
  HttpSessionT *pHttpSession;
  DbSessionT *pDbSession;
  int v1;
  double dv1, dv2;
#ifdef PROCESS_FLOW
  int pid, mem;
  double cpu;
  char process[16];
#endif

  v1 = -1;
  str[0] = 0;
  if(pNetSession->type == TYPE_HTTP){
    v1 = COMM_TYPE_HTTP;
    if(pNetSession->busi.http.url[0] == 0)
      v1 = -1;
    if(pNetSession->busi.http.beginTime.tv_sec == 0)
      v1 = -1;
    getStrTime(pNetSession->busi.http.beginTime.tv_sec, strTime);
  }
  if(pNetSession->type == TYPE_ORACLE){
    v1 = COMM_TYPE_ORACLE;
    if(pNetSession->busi.db.sql[0] == 0)
      v1 = -1;
    if(pNetSession->busi.db.beginTime.tv_sec == 0)
      v1 = -1;
    getStrTime(pNetSession->busi.db.beginTime.tv_sec, strTime);
  }
  if(pNetSession->type == TYPE_MYSQL){
    v1 = COMM_TYPE_MYSQL;
    if(pNetSession->busi.db.sql[0] == 0)
      v1 = -1;
    if(pNetSession->busi.db.beginTime.tv_sec == 0)
      v1 = -1;
    getStrTime(pNetSession->busi.db.beginTime.tv_sec, strTime);
  }
  if(pNetSession->type == TYPE_SQLSERVER){
    v1 = COMM_TYPE_SQLSERVER;
    if(pNetSession->busi.db.sql[0] == 0)
      v1 = -1;
    if(pNetSession->busi.db.beginTime.tv_sec == 0)
      v1 = -1;
    getStrTime(pNetSession->busi.db.beginTime.tv_sec, strTime);
  }
  if(v1 < 0)
    return -1;
  sprintf(s1, "%d.%d.%d.%d", pNetSession->src/256/256/256, pNetSession->src/256/256%256, pNetSession->src/256%256, pNetSession->src%256);
  sprintf(s2, "%d.%d.%d.%d", pNetSession->dst/256/256/256, pNetSession->dst/256/256%256, pNetSession->dst/256%256, pNetSession->dst%256);
  if(pNetSession->ver == 6){
    getIPV6Str(pNetSession->srcV6, s1);
    getIPV6Str(pNetSession->dstV6, s2);
  }
  getStrMac(pNetSession->macSrc, sm1);
  getStrMac(pNetSession->macDst, sm2);
  sprintf(tmp, ",\"srcMac\":\"%s\",\"dstMac\":\"%s\"", sm1, sm2);
  strcat(str, tmp);
  sprintf(str, "{\"type\":\"%d\",\"time\":\"%ld\",\"strBegintime\":\"%s\"", v1, globalValue.currTime, strTime);
  sprintf(tmp, ",\"srcMac\":\"%s\",\"dstMac\":\"%s\"", sm1, sm2);
  strcat(str, tmp);
  sprintf(tmp, ",\"src\":\"%s\",\"dst\":\"%s\",\"did\":\"%d\"", s1, s2, pNetSession->did);
  strcat(str, tmp);
#ifdef PROCESS_FLOW
  pid = 0;
  process[0] = 0;
  cpu = 0.0;
  mem = 0;
  getProgInfo2(pNetSession, &pid, process, &cpu, &mem);
  sprintf(tmp, ",\"process\":\"%s\",\"cpu\":\"%.2f\",\"mem\":\"%d KB\"", process, cpu, mem);
  strcat(str, tmp);
#endif
  sprintf(tmp, ",\"lid\":\"%d\",\"vid\":\"%d\",\"sport\":\"%d\",\"dport\":\"%d\"", pNetSession->lid, pNetSession->vid, pNetSession->sport, pNetSession->dport);
  strcat(str, tmp);
  if(pNetSession->cliConDelayUsec > 0){
    sprintf(tmp, ",\"srcConDelayUsec\":\"%d\"", pNetSession->cliConDelayUsec);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcConDelayUsec\":\"0\"");
  }
  if(pNetSession->serConDelayUsec > 0){
    sprintf(tmp, ",\"dstConDelayUsec\":\"%d\"", pNetSession->serConDelayUsec);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstConDelayUsec\":\"0\"");
  }
  if(pNetSession->type == TYPE_HTTP){
    pHttpSession = &(pNetSession->busi.http);
    delQuota(pHttpSession->domain);
    delQuota(pHttpSession->url);
    delQuota(pHttpSession->method);
    delQuota(pHttpSession->contentType);
    delQuota(pHttpSession->agent);
    format_tv(&(pHttpSession->beginTime), s1, sizeof(s1));
    format_tv(&(pHttpSession->endTime), s2, sizeof(s2));
    sprintf(tmp, ",\"begintime\":\"%s\",\"endtime\":\"%s\",\"bytes\":\"%d\",\"response\":\"%d\"", s1, s2, pNetSession->bytes, pHttpSession->response);
    strcat(str, tmp);
    sprintf(tmp, ",\"pageload\":\"%d\",\"retcode\":\"%d\",\"method\":\"%s\"", pHttpSession->pageload, pHttpSession->retcode, pHttpSession->method);
    strcat(str, tmp);
    sprintf(tmp, ",\"url\":\"%s\",\"domain\":\"%s\",\"contentType\":\"%s\"", pHttpSession->url, pHttpSession->domain, pHttpSession->contentType);
    strcat(str, tmp);
    sprintf(s1, "%d.%d.%d.%d", pNetSession->forward/256/256/256, pNetSession->forward/256/256%256, pNetSession->forward/256%256, pNetSession->forward%256);
    sprintf(tmp, ",\"agent\":\"%s\",\"forward\":\"%s\"", pHttpSession->agent, s1);
    strcat(str, tmp);
  }
  if((pNetSession->type == TYPE_ORACLE) || (pNetSession->type == TYPE_MYSQL) || (pNetSession->type == TYPE_SQLSERVER)){
    pDbSession = &(pNetSession->busi.db);
    delQuota(pDbSession->sql);
    delQuota(pDbSession->errMess);
    delQuota(pDbSession->dbname);
    delQuota(pDbSession->user);
    dv1 = 0.0;
    if(pNetSession->cntCliDelay > 0)
      dv1 = (double)pNetSession->cliDelayUsec / pNetSession->cntCliDelay;
    dv2 = 0.0;
    if(pNetSession->cntSerDelay > 0)
      dv2 = (double)pNetSession->serDelayUsec / pNetSession->cntSerDelay;
    format_tv(&(pDbSession->beginTime), s1, sizeof(s1));
    format_tv(&(pDbSession->endTime), s2, sizeof(s2));
    sprintf(tmp, ",\"begintime\":\"%s\",\"endtime\":\"%s\",\"bytes\":\"%d\",\"response\":\"%d\"", s1, s2, pNetSession->bytes, pDbSession->response);
    strcat(str, tmp);
    sprintf(tmp, ",\"sql\":\"%s\",\"resp\":\"%d\",\"err\":\"%s\",\"retcode\":\"%d\"", pDbSession->sql, pNetSession->resp, pDbSession->errMess, pDbSession->retcode);
    strcat(str, tmp);
    sprintf(tmp, ",\"dbname\":\"%s\",\"user\":\"%s\",\"srcDelayUsec\":\"%.2f\",\"dstDelayUsec\":\"%.2f\"", pDbSession->dbname, pDbSession->user, dv1, dv2);
    strcat(str, tmp);
  }
  strcat(str, "}");
  return 0;
}

int reOpenExpSock(char *str)
{
  int fd, port;
  u_int32_t addr;
  socklen_t slen;
  struct sockaddr_in sin;
  char buf[256], *p;

  port = 9015;
  strcpy(buf, str);
  p = strstr(buf, ":");
  if(p){
    *p = 0;
    p++;
    port = atoi(p);
  }
  if(getDomainAddr(buf, &sin, &addr, port))
    return -1;
  slen = sizeof(struct sockaddr_in);
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0)
    return -1;
  if (connect(fd, (struct sockaddr*)&sin, slen) < 0){
    close(fd);
    return -1;
  }
  readOnlyGlobal.isExp = 0;
  close(expSockfd);
  expSockfd = fd;
  readOnlyGlobal.expNumIP = addr;
  memcpy(&(readOnlyGlobal.expAddress), &sin, sizeof(struct sockaddr_in));
  readOnlyGlobal.isExp = 1;
  return 0;
}

int reOpenPacketSock(char *str)
{
  int fd, port;
  u_int32_t addr;
  socklen_t slen;
  struct sockaddr_in sin;
  char buf[256], *p;

  port = 4789;
  strcpy(buf, str);
  p = strstr(buf, ":");
  if(p) *p = 0;
  if(getDomainAddr(buf, &sin, &addr, port))
    return -1;
  slen = sizeof(struct sockaddr_in);
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0)
    return -1;
  if (connect(fd, (struct sockaddr*)&sin, slen) < 0){
    close(fd);
    return -1;
  }
  readOnlyGlobal.isPktExp = 0;
  close(expPktSockfd);
  expPktSockfd = fd;
  readOnlyGlobal.expPktNumIP = addr;
  memcpy(&(readOnlyGlobal.expPktAddress), &sin, sizeof(struct sockaddr_in));
  readOnlyGlobal.isPktExp = 1;
  return 0;
}

void makeJsonStr6(CommMsg6T *pCommMsg, char *str)
{
  float bytes, pkts;
  char s1[128], s2[128], sm1[64], sm2[64], tmp[1024], strTime[256];

  pkts = pCommMsg->rcvdPkts + pCommMsg->sendPkts;
  bytes = pCommMsg->sendBytes + pCommMsg->rcvdBytes;
  getStrTime(pCommMsg->time, strTime);
  getIPV6Str(pCommMsg->src, s1);
  getIPV6Str(pCommMsg->dst, s2);
  sprintf(str, "{\"type\":\"%d\",\"time\":\"%ld\",\"strTime\":\"%s\"", COMM_TYPE_COMMV6, pCommMsg->time, strTime);
#ifdef PROCESS_FLOW
  sprintf(tmp, ",\"process\":\"%s\",\"cpu\":\"%.2f\",\"mem\":\"%d KB\"", pCommMsg->process, pCommMsg->cpu, pCommMsg->mem);
  strcat(str, tmp);
#endif
  getStrMac(pCommMsg->macSrc, sm1);
  getStrMac(pCommMsg->macDst, sm2);
  sprintf(tmp, ",\"srcMac\":\"%s\",\"dstMac\":\"%s\"", sm1, sm2);
  strcat(str, tmp);
  sprintf(tmp, ",\"src\":\"%s\",\"dst\":\"%s\",\"proto\":\"%d\",\"deviceId\":\"%s\",\"did\":\"%d\"", s1, s2, pCommMsg->proto, readOnlyGlobal.devMac, pCommMsg->did);
  strcat(str, tmp);
  sprintf(tmp, ",\"lid\":\"%d\",\"vid\":\"%d\",\"sport\":\"%d\",\"dport\":\"%d\"", pCommMsg->lid, pCommMsg->vid, pCommMsg->sport, pCommMsg->dport);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcBytes\":\"%ld\",\"dstBytes\":\"%ld\",\"srcPkts\":\"%d\"", pCommMsg->sendBytes, pCommMsg->rcvdBytes, pCommMsg->sendPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"dstPkts\":\"%d\"", pCommMsg->rcvdPkts);
  strcat(str, tmp);
  if(pkts > 0){
    sprintf(tmp, ",\"avgPktLen\":\"%.2f\"", ((float)bytes)/pkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"avgPktLen\":\"0.00\"");
  }
  sprintf(tmp, ",\"srcRetransPkts\":\"%d\"", pCommMsg->sendRetransmitPkts);
  strcat(str, tmp);
  if((pCommMsg->sendPkts > 0) && (pCommMsg->sendRetransmitPkts > 0)){
    sprintf(tmp, ",\"srcLossRatio\":\"%.3f\"", (float)pCommMsg->sendRetransmitPkts/(float)pCommMsg->sendPkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcLossRatio\":\"0.00\"");
  }
  sprintf(tmp, ",\"dstRetransPkts\":\"%d\"", pCommMsg->rcvdRetransmitPkts);
  strcat(str, tmp);
  if((pCommMsg->rcvdRetransmitPkts > 0) && (pCommMsg->rcvdPkts > 0)){
    sprintf(tmp, ",\"dstLossRatio\":\"%.3f\"", (float)pCommMsg->rcvdRetransmitPkts/(float)pCommMsg->rcvdPkts);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstLossRatio\":\"0.00\"");
  }
  sprintf(tmp, ",\"srcZeroWinPkts\":\"%d\",\"dstZeroWinPkts\":\"%d\"", pCommMsg->cntSrcZeroWin, pCommMsg->cntDstZeroWin);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcSynPkts\":\"%d\",\"dstSynPkts\":\"%d\",\"largePkts\":\"%d\"", pCommMsg->sendSynPkts, pCommMsg->rcvdSynPkts, pCommMsg->largePkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcSynAckPkts\":\"%d\",\"dstSynAckPkts\":\"%d\"", pCommMsg->sendSynAckPkts, pCommMsg->rcvdSynAckPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"srcRstPkts\":\"%d\",\"dstRstPkts\":\"%d\",\"srcFinPkts\":\"%d\"", pCommMsg->sendRstPkts, pCommMsg->rcvdRstPkts, pCommMsg->sendFinPkts);
  strcat(str, tmp);
  sprintf(tmp, ",\"dstFinPkts\":\"%d\",\"srcTinyPkts\":\"%d\",\"dstTinyPkts\":\"%d\"", pCommMsg->rcvdFinPkts, pCommMsg->sendTinyPkts, pCommMsg->rcvdTinyPkts);
  strcat(str, tmp);
  if(pCommMsg->cntSrcDelay > 0){
    sprintf(tmp, ",\"srcNetDelay\":\"%.3f\"", (float)pCommMsg->srcDelayUsec/(float)(pCommMsg->cntSrcDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcNetDelay\":\"0.00\"");
  }
  if(pCommMsg->cntDstDelay > 0){
    sprintf(tmp, ",\"dstNetDelay\":\"%.3f\"", (float)pCommMsg->dstDelayUsec/(float)(pCommMsg->cntDstDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstNetDelay\":\"0.00\"");
  }
  if(pCommMsg->srcConDelayUsec > 0){
    sprintf(tmp, ",\"srcHandDelay\":\"%.3f\"", (float)pCommMsg->srcConDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcHandDelay\":\"0.00\"");
  }
  if(pCommMsg->dstConDelayUsec > 0){
    sprintf(tmp, ",\"dstHandDelay\":\"%.3f\"", (float)pCommMsg->dstConDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstHandDelay\":\"0.00\"");
  }
  if(pCommMsg->cntCustomDelay > 0){
    sprintf(tmp, ",\"responseDelay\":\"%.3f\"", (float)pCommMsg->customDelayUsec/(float)(pCommMsg->cntCustomDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"responseDelay\":\"0.00\"");
  }
  if(pCommMsg->cntLoadDelay > 0){
    sprintf(tmp, ",\"loadTransDelay\":\"%.3f\"", (float)pCommMsg->loadDelayUsec/(float)(pCommMsg->cntLoadDelay*1000));
    strcat(str, tmp);
  }else{
    strcat(str, ",\"loadTransDelay\":\"0.00\"");
  }
  if(pCommMsg->srcRetransDelayUsec > 0){
    sprintf(tmp, ",\"srcRetransDelay\":\"%.3f\"", (float)pCommMsg->srcRetransDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"srcRetransDelay\":\"0.00\"");
  }
  if(pCommMsg->dstRetransDelayUsec > 0){
    sprintf(tmp, ",\"dstRetransDelay\":\"%.3f\"", (float)pCommMsg->dstRetransDelayUsec/1000.0);
    strcat(str, tmp);
  }else{
    strcat(str, ",\"dstRetransDelay\":\"0.00\"");
  }
  strcat(str, "}");
}
