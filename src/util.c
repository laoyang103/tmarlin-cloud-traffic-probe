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
#include "log.h"
#include "util.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
extern int errno;

int initGlobalValue()
{
  int i;
  struct passwd *pwd;

  memset(&globalValue, 0x00, sizeof(GlobalValueT));
  globalValue.hashTable = (HashTableT*)malloc(sizeof(HashTableT));
  if(globalValue.hashTable == 0){
    printf("not enough money!\n");
    return -1;
  }
  memset(globalValue.hashTable, 0x00, sizeof(sizeof(HashNodeT)));
  for(i = 0; i < DEFAULT_HASH_SIZE; i++){
    if(pthread_mutex_init(&(globalValue.hashTable->node[i].mutex), 0)){
      printf("init mutex failed!\n");
      return -1;
    }
  }
  if(pthread_mutex_init(&(globalValue.processState.mutex), 0)){
    printf("init mutex failed!\n");
    return -1;
  }
  if (gethostname(readOnlyGlobal.hostname, sizeof(readOnlyGlobal.hostname))) {
    perror("gethostname error");
    return -1;
  }
  pwd = getpwuid(getuid());
  if (NULL == pwd) {
    perror("getpwuid error");
    return -1;
  } else {
    strcpy(readOnlyGlobal.hostuser, pwd->pw_name);
  }
  return 0;
}

void trim(char *str)
{
  int len, i;
  char tmp[8192], *p;

  strcpy(tmp, str);
  len = strlen(tmp);
  p = 0;
  for(i = 0; i < len; i++){
    if(tmp[i] != ' '){
      p = tmp + i;
      break;
    }
  }
  if(p)
    strcpy(str, p);
  len = strlen(str);
  for(i = len - 1; i >= 0; i--){
    if(str[i] != ' ')
      break;
    str[i] = 0;
  }
}

void toLowerCase(char *str)
{
  int i, len;

  len = strlen(str);
  for (i = 0; i < len; i++) {
    if((str[i] >= 'A') && (str[i] <= 'Z'))
      str[i] = str[i] + 32;
  }
}

void toUpperCase(char *str)
{
  int i, len;

  len = strlen(str);
  for (i = 0; i < len; i++) {
    if((str[i] >= 'a') && (str[i] <= 'z'))
      str[i] = str[i] - 32;
  }
}

time_t getGlobalTime(time_t tt)
{
  int v;

  v = (int)(tt % 10);
  return tt - v;
}

int timevalDiffUsec(const struct timeval *end, const struct timeval *start)
{
  int usec, v;

  if((end->tv_sec == 0) || (start->tv_sec == 0))
    return 0;
  usec = end->tv_sec - start->tv_sec;
  usec *= 1000000;
  v = end->tv_usec - start->tv_usec;
  usec += v;
  if(usec < 0)
    return 0;
  return usec;
}

void cloneMsgValue(CommMsgT *pCommMsg, NetSessionT *pNetSession)
{
  memcpy(pCommMsg->macSrc, pNetSession->macSrc, 6);
  memcpy(pCommMsg->macDst, pNetSession->macDst, 6);
  pCommMsg->appType = pNetSession->type;
  pCommMsg->vid = pNetSession->vid;
  pCommMsg->src = pNetSession->src;
  pCommMsg->dst = pNetSession->dst;
  pCommMsg->proto = pNetSession->proto;
  pCommMsg->sport = pNetSession->sport;
  pCommMsg->dport = pNetSession->dport;
  pCommMsg->sendPkts = pNetSession->sendPkts;
  pCommMsg->rcvdPkts = pNetSession->rcvdPkts;
  pCommMsg->sendTinyPkts = pNetSession->sendTinyPkts;
  pCommMsg->rcvdTinyPkts = pNetSession->rcvdTinyPkts;
  pCommMsg->srcConDelayUsec = pNetSession->cliConDelayUsec;
  pCommMsg->dstConDelayUsec = pNetSession->serConDelayUsec;
  pCommMsg->cntSrcDelay = pNetSession->cntCliDelay;
  pCommMsg->srcDelayUsec = pNetSession->cliDelayUsec;
  pCommMsg->srcRetransDelayUsec = pNetSession->cliRetransDelayUsec;
  pCommMsg->cntDstDelay = pNetSession->cntSerDelay;
  pCommMsg->dstDelayUsec = pNetSession->serDelayUsec;
  pCommMsg->dstRetransDelayUsec = pNetSession->serRetransDelayUsec;
  pCommMsg->sendSynPkts = pNetSession->sendSynPkts;
  pCommMsg->rcvdSynPkts = pNetSession->rcvdSynPkts;
  pCommMsg->sendSynAckPkts = pNetSession->sendSynAckPkts;
  pCommMsg->rcvdSynAckPkts = pNetSession->rcvdSynAckPkts;
  pCommMsg->sendRstPkts = pNetSession->sendRstPkts;
  pCommMsg->rcvdRstPkts = pNetSession->rcvdRstPkts;
  pCommMsg->sendFinPkts = pNetSession->sendFinPkts;
  pCommMsg->rcvdFinPkts = pNetSession->rcvdFinPkts;
  pCommMsg->sendRetransmitPkts = pNetSession->sendRetransmitPkts;
  pCommMsg->rcvdRetransmitPkts = pNetSession->rcvdRetransmitPkts;
  pCommMsg->cntCustomDelay = pNetSession->cntCustomDelay;
  pCommMsg->customDelayUsec = pNetSession->customDelayUsec;
  pCommMsg->connNum = pNetSession->connNum;
  pCommMsg->sendBytes = pNetSession->sendBytes;
  pCommMsg->rcvdBytes = pNetSession->rcvdBytes;
  pCommMsg->cntSrcWin = pNetSession->cntSrcWin;
  pCommMsg->srcWinSize = pNetSession->srcWinSize;
  pCommMsg->cntDstWin = pNetSession->cntDstWin;
  pCommMsg->dstWinSize = pNetSession->dstWinSize;
  pCommMsg->upTo64 = pNetSession->upTo64;
  pCommMsg->upTo128 = pNetSession->upTo128;
  pCommMsg->upTo256 = pNetSession->upTo256;
  pCommMsg->upTo512 = pNetSession->upTo512;
  pCommMsg->upTo1024 = pNetSession->upTo1024;
  pCommMsg->upTo1514 = pNetSession->upTo1514;
  pCommMsg->largePkts = pNetSession->largePkts;
  pCommMsg->cntSrcZeroWin = pNetSession->cntSrcZeroWin;
  pCommMsg->cntDstZeroWin = pNetSession->cntDstZeroWin;
  pCommMsg->realDirection = pNetSession->realDirection;
  pCommMsg->cntLoadDelay = pNetSession->cntLoadDelay;
  pCommMsg->loadDelayUsec = pNetSession->loadDelayUsec;
}

void cloneMsgValue6(CommMsg6T *pCommMsg, NetSessionT *pNetSession)
{
  memcpy(pCommMsg->macSrc, pNetSession->macSrc, 6);
  memcpy(pCommMsg->macDst, pNetSession->macDst, 6);
  pCommMsg->appType = pNetSession->type;
  pCommMsg->vid = pNetSession->vid;
  memcpy(pCommMsg->src, pNetSession->srcV6, 16);
  memcpy(pCommMsg->dst, pNetSession->dstV6, 16);
  pCommMsg->proto = pNetSession->proto;
  pCommMsg->sport = pNetSession->sport;
  pCommMsg->dport = pNetSession->dport;
  pCommMsg->sendPkts = pNetSession->sendPkts;
  pCommMsg->rcvdPkts = pNetSession->rcvdPkts;
  pCommMsg->sendTinyPkts = pNetSession->sendTinyPkts;
  pCommMsg->rcvdTinyPkts = pNetSession->rcvdTinyPkts;
  pCommMsg->srcConDelayUsec = pNetSession->cliConDelayUsec;
  pCommMsg->dstConDelayUsec = pNetSession->serConDelayUsec;
  pCommMsg->cntSrcDelay = pNetSession->cntCliDelay;
  pCommMsg->srcDelayUsec = pNetSession->cliDelayUsec;
  pCommMsg->srcRetransDelayUsec = pNetSession->cliRetransDelayUsec;
  pCommMsg->cntDstDelay = pNetSession->cntSerDelay;
  pCommMsg->dstDelayUsec = pNetSession->serDelayUsec;
  pCommMsg->dstRetransDelayUsec = pNetSession->serRetransDelayUsec;
  pCommMsg->sendSynPkts = pNetSession->sendSynPkts;
  pCommMsg->rcvdSynPkts = pNetSession->rcvdSynPkts;
  pCommMsg->sendSynAckPkts = pNetSession->sendSynAckPkts;
  pCommMsg->rcvdSynAckPkts = pNetSession->rcvdSynAckPkts;
  pCommMsg->sendRstPkts = pNetSession->sendRstPkts;
  pCommMsg->rcvdRstPkts = pNetSession->rcvdRstPkts;
  pCommMsg->sendFinPkts = pNetSession->sendFinPkts;
  pCommMsg->rcvdFinPkts = pNetSession->rcvdFinPkts;
  pCommMsg->sendRetransmitPkts = pNetSession->sendRetransmitPkts;
  pCommMsg->rcvdRetransmitPkts = pNetSession->rcvdRetransmitPkts;
  pCommMsg->cntCustomDelay = pNetSession->cntCustomDelay;
  pCommMsg->customDelayUsec = pNetSession->customDelayUsec;
  pCommMsg->connNum = pNetSession->connNum;
  pCommMsg->sendBytes = pNetSession->sendBytes;
  pCommMsg->rcvdBytes = pNetSession->rcvdBytes;
  pCommMsg->cntSrcWin = pNetSession->cntSrcWin;
  pCommMsg->srcWinSize = pNetSession->srcWinSize;
  pCommMsg->cntDstWin = pNetSession->cntDstWin;
  pCommMsg->dstWinSize = pNetSession->dstWinSize;
  pCommMsg->upTo64 = pNetSession->upTo64;
  pCommMsg->upTo128 = pNetSession->upTo128;
  pCommMsg->upTo256 = pNetSession->upTo256;
  pCommMsg->upTo512 = pNetSession->upTo512;
  pCommMsg->upTo1024 = pNetSession->upTo1024;
  pCommMsg->upTo1514 = pNetSession->upTo1514;
  pCommMsg->largePkts = pNetSession->largePkts;
  pCommMsg->cntSrcZeroWin = pNetSession->cntSrcZeroWin;
  pCommMsg->cntDstZeroWin = pNetSession->cntDstZeroWin;
  pCommMsg->realDirection = pNetSession->realDirection;
  pCommMsg->cntLoadDelay = pNetSession->cntLoadDelay;
  pCommMsg->loadDelayUsec = pNetSession->loadDelayUsec;
}

void clearSessionValue(NetSessionT *pNetSession)
{
  pNetSession->connNum = 0;
  pNetSession->sendPkts = 0;
  pNetSession->rcvdPkts = 0;
  pNetSession->sendTinyPkts = 0;
  pNetSession->rcvdTinyPkts = 0;
  pNetSession->serConDelayUsec = 0;
  pNetSession->cliConDelayUsec = 0;
  pNetSession->cntCliDelay = 0;
  pNetSession->cliDelayUsec = 0;
  pNetSession->cliRetransDelayUsec = 0;
  pNetSession->cntSerDelay = 0;
  pNetSession->serDelayUsec = 0;
  pNetSession->serRetransDelayUsec = 0;
  pNetSession->sendSynPkts = 0;
  pNetSession->rcvdSynPkts = 0;
  pNetSession->sendSynAckPkts = 0;
  pNetSession->rcvdSynAckPkts = 0;
  pNetSession->sendRstPkts = 0;
  pNetSession->rcvdRstPkts = 0;
  pNetSession->sendFinPkts = 0;
  pNetSession->rcvdFinPkts = 0;
  pNetSession->sendRetransmitPkts = 0;
  pNetSession->rcvdRetransmitPkts = 0;
  pNetSession->cntCustomDelay = 0;
  pNetSession->customDelayUsec = 0;
  pNetSession->sendBytes = 0;
  pNetSession->rcvdBytes = 0;
  pNetSession->cntSrcWin = 0;
  pNetSession->srcWinSize = 0;
  pNetSession->cntDstWin = 0;
  pNetSession->dstWinSize = 0;
  pNetSession->upTo64 = 0;
  pNetSession->upTo128 = 0;
  pNetSession->upTo256 = 0;
  pNetSession->upTo512 = 0;
  pNetSession->upTo1024 = 0;
  pNetSession->upTo1514 = 0;
  pNetSession->largePkts = 0;
  pNetSession->cntSrcZeroWin = 0;
  pNetSession->cntDstZeroWin = 0;
  pNetSession->cntLoadDelay = 0;
  pNetSession->loadDelayUsec = 0;
}

int findServer(u_int32_t addr, int port, int proto)
{
  int i, cnt, portFlag, protoFlag;
  HostInfoT *pHostInfo;

  cnt = readOnlyGlobal.cntHost;
  if(cnt <= 0)
    return -1;
  for (i = 0; i < cnt; i++) {
    pHostInfo = readOnlyGlobal.hostInfo + i;
    portFlag = 0;
    protoFlag = 0;
    if(addr < pHostInfo->addressLow)
      continue;
    if(addr > pHostInfo->addressHigh)
      continue;
    if(pHostInfo->port == 0)
      portFlag = 1;
    if(!portFlag && (port != pHostInfo->port))
      continue;
    if(pHostInfo->proto == 0)
      protoFlag = 1;
    if(!protoFlag && (proto != pHostInfo->proto))
      continue;
    return i;
  }
  return -1;
}

int getHashCode(u_int32_t src, u_int32_t dst, int sport, int dport)
{
  long v;

  v = src + dst + sport + dport;
  v = v % DEFAULT_HASH_SIZE;
  return (int)v;
}

void addSessionDistribute(NetSessionT *pNetSession, int len)
{
  if(len <= 64){
    pNetSession->upTo64++;
    return;
  }
  if(len <= 128){
    pNetSession->upTo128++;
    return;
  }
  if(len <= 256){
    pNetSession->upTo256++;
    return;
  }
  if(len <= 512){
    pNetSession->upTo512++;
    return;
  }
  if(len <= 1024){
    pNetSession->upTo1024++;
    return;
  }
  if(len <= 1514){
    pNetSession->upTo1514++;
    return;
  }
  pNetSession->largePkts++;
}

int getSubnet(char *buf, u_int32_t *addressLow, u_int32_t *addressHigh)
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
  if(a > 255)
    return -1;
  if(b > 255)
    return -1;
  if(c > 255)
    return -1;
  if(d > 255)
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

int getHostInfo(const char *str, HostInfoT *pHostInfo)
{
  u_int32_t addr;
  char buf[32], *p;

  strcpy(buf, str);
  p = strstr(buf, ":");
  strcpy(pHostInfo->hostStr, str);
  if(p){
    *p = 0;
    p++;
    pHostInfo->port = atoi(p);
  }
  p = strstr(buf, "-");
  if(p){
    *p = 0;
    p++;
    if(*p == '-'){
      *p = 0;
      p++;
    }
    if(getIPFromStr(buf, &addr))
      return 0;
    pHostInfo->addressLow = addr;
    if(getIPFromStr(p, &addr))
      return 0;
    pHostInfo->addressHigh = addr;
    return 1;
  }
  p = strstr(buf, "/");
  if(p){
    if(getSubnet(buf, &(pHostInfo->addressLow), &(pHostInfo->addressHigh)))
      return 0;
    return 1;
  }
  if(getIPFromStr(buf, &addr))
    return 0;
  pHostInfo->addressLow = addr;
  pHostInfo->addressHigh = addr;
  return 1;
}

int getIPFromStr(const char *str, u_int32_t *address)
{
  char buf[1024];
  u_int32_t a, b, c, d;

  strcpy(buf, str);
  if(sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d) != 4){
    return -1;
  }
  if(a > 255)
    return -1;
  if(b > 255)
    return -1;
  if(c > 255)
    return -1;
  if(d > 255)
    return -1;
  *address = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
  return 0;
}

float getRttFromSession(CommMsgT *pCommMsg)
{
  float cli, ser;
  if (0 == pCommMsg->cntSrcDelay) {
    cli = 0;
  } else {
    cli = ((float) pCommMsg->srcDelayUsec)/
      ((float) pCommMsg->cntSrcDelay);
    cli /= 1000;
  }
  if (0 == pCommMsg->cntDstDelay) {
    ser = 0;
  } else {
    ser = ((float) pCommMsg->dstDelayUsec)/
      ((float) pCommMsg->cntDstDelay);
    ser /= 1000;
  }
  return cli + ser;
}

float getRttFromSession6(CommMsg6T *pCommMsg)
{
  float cli, ser;
  if (0 == pCommMsg->cntSrcDelay) {
    cli = 0;
  } else {
    cli = ((float) pCommMsg->srcDelayUsec)/
      ((float) pCommMsg->cntSrcDelay);
    cli /= 1000;
  }
  if (0 == pCommMsg->cntDstDelay) {
    ser = 0;
  } else {
    ser = ((float) pCommMsg->dstDelayUsec)/
      ((float) pCommMsg->cntDstDelay);
    ser /= 1000;
  }
  return cli + ser;
}

float getConFromSession(CommMsgT *pCommMsg)
{
  float cli, ser;
  cli = ((float) pCommMsg->srcConDelayUsec) / 1000;
  ser = ((float) pCommMsg->dstConDelayUsec) / 1000;
  return cli + ser;
}

float getConFromSession6(CommMsg6T *pCommMsg)
{
  float cli, ser;
  cli = ((float) pCommMsg->srcConDelayUsec) / 1000;
  ser = ((float) pCommMsg->dstConDelayUsec) / 1000;
  return cli + ser;
}

float getPacketLose(CommMsgT *pCommMsg)
{
  float retrans, pkts;
  pkts = pCommMsg->sendPkts + pCommMsg->rcvdPkts;
  retrans = pCommMsg->sendRetransmitPkts + pCommMsg->rcvdRetransmitPkts;
  if (0 == pCommMsg->sendPkts + pCommMsg->rcvdPkts) {
    return 0.0f;
  } else {
    return (retrans/pkts)*100;
  }
}

float getPacketLose6(CommMsg6T *pCommMsg)
{
  float retrans, pkts;
  pkts = pCommMsg->sendPkts + pCommMsg->rcvdPkts;
  retrans = pCommMsg->sendRetransmitPkts + pCommMsg->rcvdRetransmitPkts;
  if (0 == pCommMsg->sendPkts + pCommMsg->rcvdPkts) {
    return 0.0f;
  } else {
    return (retrans/pkts)*100;
  }
}

float getDiv(float a, float b)
{
  if (0 == b) {
    return 0.0f;
  } else {
    return a/b;
  }
}

void getIPPortStrFromUint(unsigned int ip, int port, char *buf)
{
  unsigned char bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;   
  sprintf(buf, "%d.%d.%d.%d:%d", bytes[3], bytes[2], bytes[1], bytes[0], port);        
}

void getTraffic(float bytes, char *buf)
{
  float bit;
  bit = bytes*8;
  if (bit < 1048567) {
    sprintf(buf, "%.2fK", (bit/(1000*DEFAULT_REFRESH_INTERVAL)));
  } else {
    sprintf(buf, "%.2fM", (bit/(1048567*DEFAULT_REFRESH_INTERVAL)));
  }
}

void getPkts(float pkts, char *buf)
{
  if (pkts < 1024) {
    sprintf(buf, "%.2f", (pkts/DEFAULT_REFRESH_INTERVAL));
  } else if (pkts < 1048567) {
    sprintf(buf, "%.2fK", (pkts/(1000*DEFAULT_REFRESH_INTERVAL)));
  } else {
    sprintf(buf, "%.2fM", (pkts/(1048567*DEFAULT_REFRESH_INTERVAL)));
  }
}

void getCurrDate(int *year, int *month, int *day)
{
  time_t tcurr;
  struct tm stm;

  time(&tcurr);
  localtime_r(&tcurr, &stm);
  *year = stm.tm_year + 1900;
  *month = stm.tm_mon + 1;
  *day = stm.tm_mday;
}

char* format_tv(struct timeval *a, char *buf, u_int buf_len)
{
  snprintf(buf, buf_len - 1, "%u.%03u", (unsigned int)a->tv_sec, (unsigned int)a->tv_usec / 1000);
  return buf;
}

int getCmdOutOneLine(char *cmd, char *outbuf, int outlen)
{
  FILE *outfp;
  outfp = popen(cmd, "r");
  if (NULL == outfp) {
    fprintf(stderr, "can not run cmd %s\n", cmd);
    return -1;
  }
  fgets(outbuf, outlen, outfp);
  pclose(outfp);
  return strlen(outbuf);
}

int doPost(struct sockaddr_in *addr, char *path, char *poststr, char *output, FILE *outfp)
{
  int i, sockfd, isEnd = 0;
  ssize_t n, outlen = 0;
  char sendline[MAX_POSTLINE], recvline[MAX_POSTLINE], tmp;
  struct timeval timeout;

  timeout.tv_sec  = 5;
  timeout.tv_usec = 0;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (connect(sockfd, (struct sockaddr*)addr, sizeof(struct sockaddr))) {
    writeLog(PROBE_LOG_WARNING, "connect error: %s", strerror(errno));
    return -1;
  }
  if (0 != strlen(poststr) && '&' == poststr[0]) {
    snprintf(sendline, MAX_POSTLINE,
        "GET %s?method=get%s HTTP/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
        "Accept: application/json, text/javascript, */*; q=0.01\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.9\r\n"
        "Content-length: %d\r\n\r\n"
        "%s", path, poststr, 0, "");
  } else {
    snprintf(sendline, MAX_POSTLINE,
        "POST %s?vpuser=%s&vppass=%s HTTP/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
        "Accept: application/json, text/javascript, */*; q=0.01\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.9\r\n"
        "Content-length: %d\r\n\r\n"
        "%s", path, readOnlyGlobal.configInfo.username, readOnlyGlobal.configInfo.password, (int)strlen(poststr), poststr);
  }
  write(sockfd, sendline, strlen(sendline));
  while ((n = read(sockfd, recvline, MAX_POSTLINE)) > 0) {
    if (NULL == outfp) {
      tmp = recvline[n];
      recvline[n] = 0;
      if (strstr(recvline, "\r\n\r\n"))  isEnd = 1;
      recvline[n] = tmp;
      if (1 == isEnd) {
        memcpy(output + outlen, recvline, n);
        outlen += n;
      }
    } else {
      if (0 == isEnd) {
        for (i = 0; i < n; i++) if ('\r' == recvline[i] && '\r' == recvline[i+2]) break;
        fwrite(recvline+i+4, n-i-4, 1, outfp);
        outlen += (n-i-4);
        isEnd = 1;
      } else {
        fwrite(recvline, n, 1, outfp);
        outlen += n;
      }
    }
  }
  close(sockfd);
  return outlen;
}

int getDomainAddr(char *domain, struct sockaddr_in *addr, u_int32_t *IpNumPtr, u_int32_t port)
{
  in_addr_t in_addr;
  struct hostent *hptr;

  if ((hptr = gethostbyname(domain)) == NULL) {
    writeLog(PROBE_LOG_ERROR, "gethostbyname error for host: %s: %s", domain, hstrerror(h_errno));
    return -1;
  }
  in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hptr->h_addr_list)));
  if (in_addr == (in_addr_t)-1) {
    writeLog(PROBE_LOG_ERROR, "inet_addr(\"%s\")", *(hptr->h_addr_list));
    return -1;
  }

  addr->sin_addr.s_addr = in_addr;
  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  *IpNumPtr = ntohl(in_addr);
  return 0;
}

int checkHostStr(char *hostStr)
{
  int i, len; 
  int numCnt = 0, pointCnt = 0, colonCnt = 0, otherCnt = 0, subnetCnt = 0;
  len = strlen(hostStr);
  for (i = 0; i < len; i++) {
    if('0' <= hostStr[i] && hostStr[i] <= '9'){
      numCnt++;
      continue;
    }
    if('.' == hostStr[i]){
      pointCnt++;
      continue;
    }
    if(':' == hostStr[i]){
      colonCnt++;
      continue;
    }
    if('-' == hostStr[i]){
      subnetCnt++;
      continue;
    }
    if('/' == hostStr[i]){
      subnetCnt++;
      continue;
    }
    otherCnt ++;
  }
  if (pointCnt < 3) {
    writeLog(PROBE_LOG_ERROR, "Can not find IP in Analyze object \"%s\"", hostStr);
    return -1;
  }
  if (otherCnt != 0) {
    writeLog(PROBE_LOG_ERROR, "Analyze object format error \"%s\"", hostStr);
    return -1;
  }
  return 0;
}

void setHostType(char *str, int ind)
{
  HostInfoT *pHostInfo;
  char typeBuf[32];

  if(ind < 0)
    return;
  strcpy(typeBuf, str);
  toLowerCase(typeBuf);
  pHostInfo = readOnlyGlobal.hostInfo + ind;
  if(!strcmp(typeBuf, "http")){
    pHostInfo->proto = 6;
    pHostInfo->type = TYPE_HTTP;
  }
  if(!strcmp(typeBuf, "oracle")){
    pHostInfo->proto = 6;
    pHostInfo->type = TYPE_ORACLE;
  }
  if(!strcmp(typeBuf, "mysql")){
    pHostInfo->proto = 6;
    pHostInfo->type = TYPE_MYSQL;
  }
  if(!strcmp(typeBuf, "sqlserver")){
    pHostInfo->proto = 6;
    pHostInfo->type = TYPE_SQLSERVER;
  }
  if(!strcmp(typeBuf, "tcp")){
    pHostInfo->proto = 6;
  }
  if(!strcmp(typeBuf, "udp")){
    pHostInfo->proto = 17;
  }
  if(strstr(typeBuf, "tcp") && strstr(typeBuf, "udp"))
    pHostInfo->proto = 0;
}

int makeHeaderBuf(unsigned char *ubuf)
{
  ubuf[0] = 0xd4;  ubuf[1] = 0xc3;  ubuf[2] = 0xb2;  ubuf[3] = 0xa1;
  ubuf[4] = 0x02;  ubuf[5] = 0x00;  ubuf[6] = 0x04;  ubuf[7] = 0x00;
  ubuf[8] = 0x00;  ubuf[9] = 0x00;  ubuf[10] = 0x00; ubuf[11] = 0x00;
  ubuf[12] = 0x00; ubuf[13] = 0x00; ubuf[14] = 0x00; ubuf[15] = 0x00;
  ubuf[16] = 0xFF; ubuf[17] = 0xFF; ubuf[18] = 0x00; ubuf[19] = 0x00;
  ubuf[20] = 0x01; ubuf[21] = 0x00; ubuf[22] = 0x00; ubuf[23] = 0x00;
  return 24;
}

void getStrTime(time_t tt, char *str)
{
  struct tm stm;

  localtime_r(&tt, &stm);
  sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", stm.tm_year+1900, stm.tm_mon+1, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec);
}

void getFileStrTime(time_t tt, char *str)
{
  struct tm stm;

  localtime_r(&tt, &stm);
  sprintf(str, "%d%02d%02d%02d%02d%02d", stm.tm_year+1900, stm.tm_mon+1, stm.tm_mday, stm.tm_hour, stm.tm_min, stm.tm_sec);
}

int chkDir(char *str)
{
  char buf[1024];

  getcwd(buf, 1024);
  if(chdir(str))
    return -1;
  chdir(buf);
  return 0;
}

int checkAppType(const u_char *payload, int payloadLen)
{
  const char *p;
  int flag;

  flag = 0;
  p = (const char*)payload;
  if(!strncmp(p, "GET ", 4))
    flag = 1;
  if(!strncmp(p, "POST ", 5))
    flag = 1;
  if(flag == 0)
    return 0;
  p = strstr(p, "HTTP");
  if(p == 0)
    return 0;
  return TYPE_HTTP;
}

void getHexStr(u_char uch, char *str)
{
  int v1, v2;

  v1 = uch / 16;
  v2 = uch % 16;
  str[0] = v1 + '0';
  if(v1 >= 10)
    str[0] = v1 + 55;
  str[1] = v2 + '0';
  if(v2 >= 10)
    str[1] = v2 + 55;
  str[2] = 0;
}

void getIPV6Str(u_char *ipV6, char *buf)
{
  int i, flag;
  char tmp[4];

  buf[0] = 0;
  flag = 0;
  for(i = 0; i < 16; i++){
    getHexStr(ipV6[i], tmp);
    if(i == 0){
      strcpy(buf, tmp);
      continue;
    }
    if((i % 2) == 0){
      if((ipV6[i] == 0) && (ipV6[i+1] == 0)){
        if(flag == 0){
          strcat(buf, ":");
          flag = 1;
        }
        i += 1;
        continue;
      }
      strcat(buf, ":");
      if(ipV6[i] == 0)
        continue;
    }
    strcat(buf, tmp);
    flag = 0;
  }
}

void getIPV6PortStrFromUint(u_char *ipV6, int port, char *buf)
{
  char tmp[1024];

  getIPV6Str(ipV6, tmp);
  sprintf(buf, "%s-%d", tmp, port);
}

void getStrMac(u_char *mac, char *buf)
{
  int i;
  char tmp[4];

  for(i = 0; i < 6; i++){
    getHexStr(mac[i], tmp);
    if(i == 0){
      strcpy(buf, tmp);
      continue;
    }
    strcat(buf, ":");
    strcat(buf, tmp);
  }
}

char getHex(char ch)
{
  if((ch >= '0') && (ch <= '9'))
    return ch - '0';
  if((ch >= 'a') && (ch <= 'f'))
    return ch - 'a' + 10;
  if((ch >= 'A') && (ch <= 'F'))
    return ch - 'A' + 10;
  return -1;
}

int getUchar(char *str, u_char *u1, u_char *u2)
{
  char v1, v2, v3, v4, *p;
  char tmp[32];
  int len, ind;

  p = str;
  strcpy(tmp, "0000");
  if(p[0] == ':')
    p++;
  len = strlen(p);
  ind = 4 - len;
  if(ind < 0)
    ind = 0;
  strcpy(tmp + ind, p);
  v1 = getHex(tmp[0]);
  if(v1 < 0)
    return -1;
  v2 = getHex(tmp[1]);
  if(v2 < 0)
    return -1;
  v3 = getHex(tmp[2]);
  if(v3 < 0)
    return -1;
  v4 = getHex(tmp[3]);
  if(v4 < 0)
    return -1;
  *u1 = (u_char)v1 * 16 + v2;
  *u2 = (u_char)v3 * 16 + v4;
  return 0;
}

int getUbyteIP6(char *str, u_char *addr)
{
  int i, len, ind, cnt1, cnt2, flag;
  char tmp[32], buf[256];
  u_char ubuf1[16], ubuf2[16], u1, u2;

  cnt1 = 0;
  cnt2 = 0;
  flag = 0;
  ind = 0;
  memset(ubuf1, 0x00, 16);
  strcpy(buf, str);
  if(str[0] == ':')
    strcpy(buf, str+1);
  len = strlen(buf);
  buf[len] = ':';
  len++;
  buf[len] = 0;
  for(i = 0; i < len; i++){
    if(buf[i] == ':'){
      if(getUchar(tmp, &u1, &u2))
        return -1;
      if(flag == 0){
        ubuf1[cnt1++] = u1;
        ubuf1[cnt1++] = u2;
      }else{
        ubuf2[cnt2++] = u1;
        ubuf2[cnt2++] = u2;
      }
      ind = 0;
      if(buf[i+1] == ':'){
        flag = 1;
        i++;
      }
      continue;
    }
    tmp[ind] = buf[i];
    ind++;
    tmp[ind] = 0;
  }
  memcpy(addr, ubuf1, 16);
  if(cnt1 >= 16)
    return 0;
  ind = 16 - cnt2;
  memcpy(addr + ind, ubuf2, cnt2);
  return 0;
}
