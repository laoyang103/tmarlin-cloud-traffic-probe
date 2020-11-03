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
#include "ui.h"
#include "data.h"
#include "check.h"
#include "commpair.h"
#ifdef PROCESS_FLOW
#include "inode.h"
#endif

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
int cntTotalSession, cntTotalSession6;
CommMsgT commMsgs[MAX_SESSION_COUNT];
CommMsg6T commMsgs6[MAX_SESSION_COUNT];

void storeMaxSession(CommMsgT *pCommMsg);
void storeMaxSession6(CommMsg6T *pCommMsg);

void scanFun()
{
  int i, j, k, l, m, pkt, byte, cntSession;
  int drop, response, cntResp, cntCliDelay;
  int cliDelayUsec, cntSerDelay, serDelayUsec;
  time_t tcurr, tRealCurr, tlastHeart;
  float rtt, resp, loss;
  CommMsgT comms[DEFAULT_HASH_LENGTH], *pCommMsg;
  CommMsg6T comms6[DEFAULT_HASH_LENGTH], *pCommMsg6;
  HashNodeT *pHashNode;
  NetSessionT *pNetSession, exportSessions[DEFAULT_HASH_LENGTH];

  time(&tcurr);
  tcurr = getGlobalTime(tcurr);
  tRealCurr = globalValue.realCurrTime;
  tlastHeart = 0;
  cntSession = 0;
  cntTotalSession = 0;
  cntTotalSession6 = 0;
  response = 0;
  cntResp = 0;
  cntCliDelay = 0;
  cliDelayUsec = 0;
  cntSerDelay = 0;
  serDelayUsec = 0;
  memset(commMsgs, 0x00, sizeof(CommMsgT) * MAX_SESSION_COUNT);
  memset(commMsgs6, 0x00, sizeof(CommMsg6T) * MAX_SESSION_COUNT);
  for(i = 0; i < DEFAULT_HASH_SIZE; i++){
    pHashNode = globalValue.hashTable->node + i;
    k = 0;
    l = 0;
    m = 0;
    pthread_mutex_lock(&(pHashNode->mutex));
    for(j = 0; j < DEFAULT_HASH_LENGTH; j++){
      pNetSession = pHashNode->session + j;
      if(pNetSession->valid == 0)
        continue;
      cntSession++;
      if(pNetSession->customDelayUsec > 0){
        response += pNetSession->customDelayUsec;
        cntResp += pNetSession->cntCustomDelay;
      }
      if(pNetSession->cliDelayUsec > 0){
        cliDelayUsec += pNetSession->cliDelayUsec;
        cntCliDelay += pNetSession->cntCliDelay;
      }
      if(pNetSession->serDelayUsec > 0){
        serDelayUsec += pNetSession->serDelayUsec;
        cntSerDelay += pNetSession->cntSerDelay;
      }
      if(tRealCurr - pNetSession->lastPktTime.tv_sec >= readOnlyGlobal.sessionTimeOut){
        if((pNetSession->sendPkts + pNetSession->rcvdPkts) > 0){
          if(pNetSession->ver == 6){
            cloneMsgValue6(comms6 + m, pNetSession);
            m++;
          }else{
            cloneMsgValue(comms + k, pNetSession);
            k++;
          }
        }
        if(pNetSession->type > 0){
          memcpy(exportSessions + l, pNetSession, sizeof(NetSessionT));
          l++;
        }
        pNetSession->valid = 0;
        continue;
      }
      if((pNetSession->state >= FLAG_STATE_FIN1_ACK0) && (tRealCurr - pNetSession->lastPktTime.tv_sec >= 2)){
        if((pNetSession->sendPkts + pNetSession->rcvdPkts) > 0){
          if(pNetSession->ver == 6){
            cloneMsgValue6(comms6 + m, pNetSession);
            m++;
          }else{
            cloneMsgValue(comms + k, pNetSession);
            k++;
          }
        }
        if(pNetSession->type > 0){
          memcpy(exportSessions + l, pNetSession, sizeof(NetSessionT));
          l++;
        }
        pNetSession->valid = 0;
        continue;
      }
      if((pNetSession->sendPkts + pNetSession->rcvdPkts) == 0)
        continue;
      if(pNetSession->ver == 6){
        cloneMsgValue6(comms6 + m, pNetSession);
        m++;
      }else{
        cloneMsgValue(comms + k, pNetSession);
        k++;
      }
      clearSessionValue(pNetSession); // Clear session KPI information
    }
    pthread_mutex_unlock(&(pHashNode->mutex));
    for(j = 0; j < k; j++){
      pCommMsg = comms + j;
#ifdef PROCESS_FLOW
      pCommMsg->pid = 0;
      pCommMsg->process[0] = 0;
      pCommMsg->cpu = 0.0;
      pCommMsg->mem = 0;
      getProgInfo(pCommMsg, &(pCommMsg->pid), pCommMsg->process, &(pCommMsg->cpu), &(pCommMsg->mem));
#endif
      putCommpairSession(pCommMsg);
      storeMaxSession(pCommMsg); // Save session with the most traffic
    }
    for(j = 0; j < m; j++){
      pCommMsg6 = comms6 + j;
#ifdef PROCESS_FLOW
      pCommMsg6->pid = 0;
      pCommMsg6->process[0] = 0;
      pCommMsg6->cpu = 0.0;
      pCommMsg6->mem = 0;
#endif
      putCommpairSession6(pCommMsg6);
      storeMaxSession6(pCommMsg6); // Save session with the most traffic
    }
    for(j = 0; j < l; j++){
      exportBusinessData(exportSessions + j);
    }
  }
  exportCommpairData(tcurr);  // Send communication pair information, using JSON format
  exportCommpairData6(tcurr);
  checkLog();
  pthread_mutex_lock(&(globalValue.processState.mutex)); // Record global information
  byte = globalValue.processState.byte;
  pkt = globalValue.processState.pkt;
  drop = globalValue.processState.retran;
  globalValue.processState.byte = 0;
  globalValue.processState.pkt = 0;
  globalValue.processState.retran = 0;
  pthread_mutex_unlock(&(globalValue.processState.mutex));
  loss = 0.0;
  rtt = 0.0;
  resp = 0.0;
  if(pkt > 0)
    loss = (float)drop / (float)pkt;
  if(cntResp > 0)
    resp = (float)response / (float)cntResp / 1000;
  if(cntCliDelay > 0)
    rtt = (float)cliDelayUsec / (float)cntCliDelay / 1000;
  if(cntSerDelay > 0)
    rtt += (float)serDelayUsec / (float)cntSerDelay / 1000;
  printTop(commMsgs, cntTotalSession, commMsgs6, cntTotalSession6, byte, pkt, cntSession, rtt, resp, loss);  // Display grid information
  writeFileLogScreen(PROBE_LOG_MESSAGE, "[PcapRecv=%d] [PcapDrop=%d] [Ratio=%.2f] [BYTES=%d] [PACKET=%d] [SESSION:%d] [CPU=%.2f] [MEM=%.2f]", 
      globalValue.pcapRecv, globalValue.pcapDrop, (float)globalValue.pcapDrop/(float)globalValue.pcapRecv, byte, pkt, cntSession, 
      globalValue.gcpu, globalValue.gmem);
  if (tcurr - tlastHeart > 300) {
    tlastHeart = tcurr;
    if (readOnlyGlobal.isChk) chkLicense();
  }
  return;
}

void storeMaxSession(CommMsgT *pCommMsg)
{
  int i, ind;
  u_int32_t v;

  if(cntTotalSession == 0){
    memcpy(commMsgs + cntTotalSession, pCommMsg, sizeof(CommMsgT));
    cntTotalSession++;
    return;
  }
  ind = -1;
  v = pCommMsg->sendPkts + pCommMsg->rcvdPkts;
  for(i = 0; i < cntTotalSession; i++){
    if(v < (commMsgs[i].sendPkts + commMsgs[i].rcvdPkts)){
      ind = i;
      break;
    }
  }
  if(ind < 0){
    if(cntTotalSession < MAX_SESSION_COUNT){
      memcpy(commMsgs + cntTotalSession, pCommMsg, sizeof(CommMsgT));
      cntTotalSession++;
    }
    return;
  }
  for(i = cntTotalSession-1; i >= ind; i--){
    if(i == (MAX_SESSION_COUNT - 1))
      continue;
    memcpy(commMsgs + i + 1, commMsgs + i, sizeof(CommMsgT));
  }
  memcpy(commMsgs + ind, pCommMsg, sizeof(CommMsgT));
  cntTotalSession++;
  if(cntTotalSession > MAX_SESSION_COUNT)
    cntTotalSession = MAX_SESSION_COUNT;
  return;
}

void storeMaxSession6(CommMsg6T *pCommMsg)
{
  int i, ind;
  u_int32_t v;

  if(cntTotalSession6 == 0){
    memcpy(commMsgs6 + cntTotalSession6, pCommMsg, sizeof(CommMsg6T));
    cntTotalSession6++;
    return;
  }
  ind = -1;
  v = pCommMsg->sendPkts + pCommMsg->rcvdPkts;
  for(i = 0; i < cntTotalSession6; i++){
    if(v < (commMsgs6[i].sendPkts + commMsgs6[i].rcvdPkts)){
      ind = i;
      break;
    }
  }
  if(ind < 0){
    if(cntTotalSession6 < MAX_SESSION_COUNT){
      memcpy(commMsgs6 + cntTotalSession6, pCommMsg, sizeof(CommMsg6T));
      cntTotalSession6++;
    }
    return;
  }
  for(i = cntTotalSession6-1; i >= ind; i--){
    if(i == (MAX_SESSION_COUNT - 1))
      continue;
    memcpy(commMsgs6 + i + 1, commMsgs6 + i, sizeof(CommMsg6T));
  }
  memcpy(commMsgs6 + ind, pCommMsg, sizeof(CommMsg6T));
  cntTotalSession6++;
  if(cntTotalSession6 > MAX_SESSION_COUNT)
    cntTotalSession6 = MAX_SESSION_COUNT;
  return;
}
