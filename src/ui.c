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
#include "data.h"
#ifdef PROCESS_FLOW
#include "inode.h"
#endif

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

static int fieldLen[100], totalLen;
static char *fieldMinus[32];
static char *fieldName[] = {
 "Source                                         ",
 "Destination                                    ",
 "Proto",
#ifdef PROCESS_FLOW
 "Program   ",
 "\%CPU    ",
 "\%MEM     ",
#endif
 "Traffic ",
 "Packet ",
 "PktLose ",
 "NetLatency",
 "HandTime  ",
 "respTime  ",
 "loadTime  ",
 NULL
};

int initUI() // Initializing grid fields
{
  int i;
  for (i = 0; NULL != fieldName[i]; i++) {
    fieldLen[i] = strlen(fieldName[i]);
    fieldMinus[i] = (char *)malloc(fieldLen[i] + 5);
    strncpy(fieldMinus[i], "+------------------------------------------------------------------------", fieldLen[i] + 1);
    fieldMinus[i][fieldLen[i] + 1] = 0;
    totalLen += strlen(fieldMinus[i]);
  }
  totalLen += 1;
  return 0;
}

static void printYellowGrid(char *space, char *field[])
{
  int i;
  for (i = 0; NULL != fieldName[i]; i++) {
    printf("%s\033[33m%s\033[0m", space, field[i]);
  }
  if(*space == '|'){
    printf("|\n");
    return;
  }
  printf("+\n");
}

static void printGrid(char *space, char *field[])
{
  int i;
  for (i = 0; NULL != fieldName[i]; i++) {
    printf("%s%s", space, field[i]);
  }
  if(*space == '|'){
    printf("|\n");
    return;
  }
  printf("+\n");
}

static void printMainInfo()
{
  time_t tcurr;
  struct tm stm;
  char buf[1024];
  int i, yy, mm, dd, hh, mi, ss;

  tcurr = time(NULL);
  localtime_r(&tcurr, &stm);
  yy = stm.tm_year + 1900;
  mm = stm.tm_mon + 1;
  dd = stm.tm_mday;
  hh = stm.tm_hour;
  mi = stm.tm_min;
  ss = stm.tm_sec;
  sprintf(buf, "|\033[32mTime: %d-%02d-%02d %02d:%02d:%02d    Capture on: %s    IP: %s    Sort: Traffic\033[0m",
      yy, mm, dd, hh, mi, ss, readOnlyGlobal.configInfo.devName, inet_ntoa(readOnlyGlobal.devAddress.sin_addr));
  for(i = strlen(buf); i < totalLen+9; i++){
    buf[i] = ' ';
  }
  buf[totalLen+8] = '|';
  buf[totalLen+9] = 0;
  printf("%s\n", buf);
}

void printMsg6(CommMsg6T *pCommMsg);
void printMsg(CommMsgT *pCommMsg);

void printTop(CommMsgT *list, int size, CommMsg6T *list6, int size6, int bytes, int pkt, int session, float rtt, float resp, float lose)
{
  int i, ind1, ind2, v1, v2;
  char buf[64], tmp[1024], tmp2[64];
  CommMsgT *pCommMsg;
  CommMsg6T *pCommMsg6;

  printf("\033[2J\033[1;1H");

  if(!readOnlyGlobal.licenseRun){  // Print invalid information
    printGrid("", fieldMinus);
    sprintf(tmp, "|\033[41;36mLicense has expired, please purchase a new license or download free version\033[0m");
    for(i = strlen(tmp); i < totalLen+12; i++)
      tmp[i] = ' ';
    tmp[totalLen+11] = '|';
    tmp[totalLen+12] = 0;
    printf("%s\n", tmp);
  }
  printGrid("", fieldMinus);  // Print head information
  sprintf(tmp, "|\033[32mtmarlin Cloud Traffic Probe 3.0 / Ver 3.0   ID: %s    USER: %s\033[0m", readOnlyGlobal.devMac, readOnlyGlobal.configInfo.username);
  for(i = strlen(tmp); i < totalLen+9; i++){
    tmp[i] = ' ';
  }
  tmp[totalLen+8] = '|';
  tmp[totalLen+9] = 0;
  printf("%s\n", tmp);
  getStrTime(readOnlyGlobal.licenseValid, buf);
  buf[10] = 0;  // Print version information
  sprintf(tmp, "|\033[32mCurrent version %s, Expiration date : %s\033[0m", readOnlyGlobal.sysVersion, buf);
  for(i = strlen(tmp); i < totalLen+9; i++){
    tmp[i] = ' ';
  }
  tmp[totalLen+8] = '|';
  tmp[totalLen+9] = 0;
  printf("%s\n", tmp);
  printGrid("", fieldMinus);
  printMainInfo();
  printGrid("", fieldMinus);
  printYellowGrid("|", fieldName);
  printGrid("", fieldMinus);
  ind1 = size - 1;
  ind2 = size6 - 1;
  for(i = 0; i < MAX_SESSION_COUNT; i++){
    v1 = 0;
    v2 = 0;
    if(ind1 >= 0){
      pCommMsg = list + ind1;
      v1 = pCommMsg->sendPkts + pCommMsg->rcvdPkts;
    }
    if(ind2 >= 0){
      pCommMsg6 = list6 + ind2;
      v2 = pCommMsg6->sendPkts + pCommMsg6->rcvdPkts;
    }
    if((v1 == 0) && (v2 == 0))
      continue;
    if(v2 > v1){
      printMsg6(pCommMsg6);
      ind2--;
    }
    if(v1 > v2){
      printMsg(pCommMsg);
      ind1--;
    }
  }
  printGrid("", fieldMinus);
  getTraffic(bytes, buf);
  getPkts(pkt, tmp2);  // Print tail information
  sprintf(tmp, "|\033[32mTen seconds statistics    Traffic: %s   Packet: %s   Session: %d   Pkt Lose: %.2f %%   Ave Rtt: %.2f ms   Ave resp: %.2f ms\033[0m", buf, tmp2, session, lose, rtt, resp);
  for(i = strlen(tmp); i < totalLen+9; i++){
    tmp[i] = ' ';
  }
  tmp[totalLen+8] = '|';
  tmp[totalLen+9] = 0;
  printf("%s\n", tmp);
  printGrid("", fieldMinus);
  printf("\n");
}

void printMsg(CommMsgT *pCommMsg)
{
#ifdef PROCESS_FLOW
  int pid;
  char prog[64], strCPU[64], strMEM[64];
#endif
  char buf[64];

#ifdef PROCESS_FLOW
    pid = pCommMsg->pid;
    prog[0] = 0;
    strCPU[0] = 0;
    strMEM[0] = 0;
    if(pid != 0){
      strcpy(prog, pCommMsg->process);
      sprintf(strCPU, "%.2f", pCommMsg->cpu);
      sprintf(strMEM, "%d KB", pCommMsg->mem);
    }
#endif
    getIPPortStrFromUint(pCommMsg->src, pCommMsg->sport, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_SOURCE], buf);  // First column is source IP:PORT
    getIPPortStrFromUint(pCommMsg->dst, pCommMsg->dport, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_SOURCE], buf);  // Second column is destination IP:PORT
    strcpy(buf, "TCP");
    if(pCommMsg->proto == 17)
      strcpy(buf, "UDP");
    if(pCommMsg->proto == 1)
      strcpy(buf, "ICMP");
    if(pCommMsg->appType == TYPE_HTTP)
      strcpy(buf, "HTTP");
    if(pCommMsg->appType == TYPE_MYSQL)
      strcpy(buf, "MYSQL");
    if(pCommMsg->appType == TYPE_ORACLE)
      strcpy(buf, "ORACLE");
    if(pCommMsg->appType == TYPE_SQLSERVER)
      strcpy(buf, "SQLSERVER");
    printf("|%-*s", fieldLen[TOP_FIELD_PROTO], buf);  // Third column is proto
#ifdef PROCESS_FLOW
    printf("|%-*s", fieldLen[TOP_FIELD_PROGRAM], prog);
    printf("|%-*s", fieldLen[TOP_FIELD_CPU], strCPU);
    printf("|%-*s", fieldLen[TOP_FIELD_MEM], strMEM);
#endif
    getTraffic(pCommMsg->sendBytes + pCommMsg->rcvdBytes, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_TRAFFIC], buf);   // Print important KPI information
    getPkts(pCommMsg->sendPkts + pCommMsg->rcvdPkts, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_PACKETS], buf);
    printf("|%-*.2f", fieldLen[TOP_FIELD_PKTLOSE], getPacketLose(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_RTTDELAY], getRttFromSession(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_SYNDELAY], getConFromSession(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_RESPDELAY], getDiv(pCommMsg->customDelayUsec, pCommMsg->cntCustomDelay)/1000.0);
    printf("|%-*.2f", fieldLen[TOP_FIELD_LOADDELAY], getDiv(pCommMsg->loadDelayUsec, pCommMsg->cntLoadDelay)/1000.0);
    printf("|\n");
}

void printMsg6(CommMsg6T *pCommMsg)
{
#ifdef PROCESS_FLOW
  int pid;
  char prog[64], strCPU[64], strMEM[64];
#endif
  char buf[64];

#ifdef PROCESS_FLOW
    pid = pCommMsg->pid;
    prog[0] = 0;
    strCPU[0] = 0;
    strMEM[0] = 0;
    if(pid != 0){
      strcpy(prog, pCommMsg->process);
      sprintf(strCPU, "%.2f", pCommMsg->cpu);
      sprintf(strMEM, "%d KB", pCommMsg->mem);
    }
#endif
    getIPV6PortStrFromUint(pCommMsg->src, pCommMsg->sport, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_SOURCE], buf);
    getIPV6PortStrFromUint(pCommMsg->dst, pCommMsg->dport, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_SOURCE], buf);
    strcpy(buf, "TCP");
    if(pCommMsg->proto == 17)
      strcpy(buf, "UDP");
    if(pCommMsg->proto == 1)
      strcpy(buf, "ICMP");
    if(pCommMsg->appType == TYPE_HTTP)
      strcpy(buf, "HTTP");
    if(pCommMsg->appType == TYPE_MYSQL)
      strcpy(buf, "MYSQL");
    if(pCommMsg->appType == TYPE_ORACLE)
      strcpy(buf, "ORACLE");
    if(pCommMsg->appType == TYPE_SQLSERVER)
      strcpy(buf, "SQLSERVER");
    printf("|%-*s", fieldLen[TOP_FIELD_PROTO], buf);
#ifdef PROCESS_FLOW
    printf("|%-*s", fieldLen[TOP_FIELD_PROGRAM], prog);
    printf("|%-*s", fieldLen[TOP_FIELD_CPU], strCPU);
    printf("|%-*s", fieldLen[TOP_FIELD_MEM], strMEM);
#endif
    getTraffic(pCommMsg->sendBytes + pCommMsg->rcvdBytes, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_TRAFFIC], buf);
    getPkts(pCommMsg->sendPkts + pCommMsg->rcvdPkts, buf);
    printf("|%-*s", fieldLen[TOP_FIELD_PACKETS], buf);
    printf("|%-*.2f", fieldLen[TOP_FIELD_PKTLOSE], getPacketLose6(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_RTTDELAY], getRttFromSession6(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_SYNDELAY], getConFromSession6(pCommMsg));
    printf("|%-*.2f", fieldLen[TOP_FIELD_RESPDELAY], getDiv(pCommMsg->customDelayUsec, pCommMsg->cntCustomDelay)/1000.0);
    printf("|%-*.2f", fieldLen[TOP_FIELD_LOADDELAY], getDiv(pCommMsg->loadDelayUsec, pCommMsg->cntLoadDelay)/1000.0);
    printf("|\n");
}
