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
#include "commpair.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
CommPairHashTableT *pHashTable;
CommPairHashTable6T *pHashTable6;

void mergeCommPair(CommMsgT *dst, CommMsgT *src);
void mergeCommPair6(CommMsg6T *dst, CommMsg6T *src);

int initCommPair()
{
  pHashTable = (CommPairHashTableT*)malloc(sizeof(CommPairHashTableT));  // init IPV4 commpair hash table
  if(pHashTable == 0)
    return -1;
  memset(pHashTable, 0x00, sizeof(CommPairHashTableT));

  pHashTable6 = (CommPairHashTable6T*)malloc(sizeof(CommPairHashTable6T));  // init IPV6 commpair hash table
  if(pHashTable6 == 0)
    return -1;
  memset(pHashTable6, 0x00, sizeof(CommPairHashTable6T));

  return 0;
}

void putCommpairSession(CommMsgT *pCommMsg)
{
  int i, hashcode, ind;
  CommPairHashNodeT *pnode;
  CommMsgT *pPair;

  hashcode = (pCommMsg->src + pCommMsg->dst) % COMMPAIR_HASH_SIZE;
  pnode = pHashTable->node + hashcode; //Hash algorithm
  ind = -1;
  for(i = 0; i < COMMPAIR_HASH_LENGTH; i++){
    pPair = pnode->commpair + i;
    if((pPair->appType == 0) && (ind < 0)){
      ind = i;
      break;
    }
    if((pCommMsg->src == pPair->src) && (pCommMsg->dst == pPair->dst) && (pCommMsg->dport == pPair->dport)){
      mergeCommPair(pPair, pCommMsg);  //Merge communication to KPI
      return;
    }
    if((pCommMsg->src == pPair->dst) && (pCommMsg->dst == pPair->src) && (pCommMsg->dport == pPair->sport)){
      mergeCommPair(pPair, pCommMsg);
      return;
    }
  }
  if(ind < 0)
    return;
  pPair = pnode->commpair + ind;
  mergeCommPair(pPair, pCommMsg);
}

void putCommpairSession6(CommMsg6T *pCommMsg)
{
  int i, hashcode, ind;
  CommPairHashNode6T *pnode;
  CommMsg6T *pPair;
  u_int32_t src, dst;

  memcpy(&src, pCommMsg->src+12, 4);
  memcpy(&dst, pCommMsg->dst+12, 4);
  hashcode = (src + dst) % COMMPAIR_HASH_SIZE;
  pnode = pHashTable6->node + hashcode;
  ind = -1;
  for(i = 0; i < COMMPAIR_HASH_LENGTH; i++){
    pPair = pnode->commpair + i;
    if((pPair->appType == 0) && (ind < 0)){
      ind = i;
      break;
    }
    if(!memcmp(pCommMsg->src, pPair->src, 16) && !memcmp(pCommMsg->dst, pPair->dst, 16) && (pCommMsg->dport == pPair->dport)){
      mergeCommPair6(pPair, pCommMsg);
      return;
    }
    if(!memcmp(pCommMsg->src, pPair->dst, 16) && !memcmp(pCommMsg->dst, pPair->src, 16) && (pCommMsg->dport == pPair->sport)){
      mergeCommPair6(pPair, pCommMsg);
      return;
    }
  }
  if(ind < 0)
    return;
  pPair = pnode->commpair + ind;
  mergeCommPair6(pPair, pCommMsg);
}

void mergeCommPair(CommMsgT *dst, CommMsgT *src)
{
  if(dst->appType == 0){
    memcpy(dst, src, sizeof(CommMsgT));
    dst->appType = 1;
    dst->sport = 0;
    return;
  }
  dst->sendPkts += src->sendPkts;
  dst->rcvdPkts += src->rcvdPkts;
  dst->sendTinyPkts += src->sendTinyPkts;
  dst->rcvdTinyPkts += src->rcvdTinyPkts;
  dst->srcConDelayUsec += src->srcConDelayUsec;
  dst->dstConDelayUsec += src->dstConDelayUsec;
  dst->cntSrcDelay += src->cntSrcDelay;
  dst->srcDelayUsec += src->srcDelayUsec;
  dst->srcRetransDelayUsec += src->srcRetransDelayUsec;
  dst->cntDstDelay += src->cntDstDelay;
  dst->dstDelayUsec += src->dstDelayUsec;
  dst->dstRetransDelayUsec += src->dstRetransDelayUsec;
  dst->connNum += src->connNum;
  dst->sendSynPkts += src->sendSynPkts;   
  dst->rcvdSynPkts += src->rcvdSynPkts;
  dst->sendSynAckPkts += src->sendSynAckPkts;
  dst->rcvdSynAckPkts += src->rcvdSynAckPkts;
  dst->sendRstPkts += src->sendRstPkts;
  dst->rcvdRstPkts += src->rcvdRstPkts;
  dst->sendFinPkts += src->sendFinPkts;
  dst->rcvdFinPkts += src->rcvdFinPkts;
  dst->sendRetransmitPkts += src->sendRetransmitPkts;
  dst->rcvdRetransmitPkts += src->rcvdRetransmitPkts;
  dst->cntCustomDelay += src->cntCustomDelay;
  dst->customDelayUsec += src->customDelayUsec;
  dst->upTo64 += src->upTo64;
  dst->upTo128 += src->upTo128;
  dst->upTo256 += src->upTo256;
  dst->upTo512 += src->upTo512;
  dst->upTo1024 += src->upTo1024;
  dst->upTo1514 += src->upTo1514;
  dst->largePkts += src->largePkts;
  dst->cntSrcWin += src->cntSrcWin;
  dst->srcWinSize += src->srcWinSize;
  dst->cntDstWin += src->cntDstWin;
  dst->dstWinSize += src->dstWinSize;
  dst->cntSrcZeroWin += src->cntSrcZeroWin;
  dst->cntDstZeroWin += src->cntDstZeroWin;
  dst->cntLoadDelay += src->cntLoadDelay;
  dst->loadDelayUsec += src->loadDelayUsec;
  dst->sendBytes += src->sendBytes;
  dst->rcvdBytes += src->rcvdBytes;
}

void mergeCommPair6(CommMsg6T *dst, CommMsg6T *src)
{
  if(dst->appType == 0){
    memcpy(dst, src, sizeof(CommMsgT));
    dst->appType = 1;
    dst->sport = 0;
    return;
  }
  dst->sendPkts += src->sendPkts;
  dst->rcvdPkts += src->rcvdPkts;
  dst->sendTinyPkts += src->sendTinyPkts;
  dst->rcvdTinyPkts += src->rcvdTinyPkts;
  dst->srcConDelayUsec += src->srcConDelayUsec;
  dst->dstConDelayUsec += src->dstConDelayUsec;
  dst->cntSrcDelay += src->cntSrcDelay;
  dst->srcDelayUsec += src->srcDelayUsec;
  dst->srcRetransDelayUsec += src->srcRetransDelayUsec;
  dst->cntDstDelay += src->cntDstDelay;
  dst->dstDelayUsec += src->dstDelayUsec;
  dst->dstRetransDelayUsec += src->dstRetransDelayUsec;
  dst->connNum += src->connNum;
  dst->sendSynPkts += src->sendSynPkts;   
  dst->rcvdSynPkts += src->rcvdSynPkts;
  dst->sendSynAckPkts += src->sendSynAckPkts;
  dst->rcvdSynAckPkts += src->rcvdSynAckPkts;
  dst->sendRstPkts += src->sendRstPkts;
  dst->rcvdRstPkts += src->rcvdRstPkts;
  dst->sendFinPkts += src->sendFinPkts;
  dst->rcvdFinPkts += src->rcvdFinPkts;
  dst->sendRetransmitPkts += src->sendRetransmitPkts;
  dst->rcvdRetransmitPkts += src->rcvdRetransmitPkts;
  dst->cntCustomDelay += src->cntCustomDelay;
  dst->customDelayUsec += src->customDelayUsec;
  dst->upTo64 += src->upTo64;
  dst->upTo128 += src->upTo128;
  dst->upTo256 += src->upTo256;
  dst->upTo512 += src->upTo512;
  dst->upTo1024 += src->upTo1024;
  dst->upTo1514 += src->upTo1514;
  dst->largePkts += src->largePkts;
  dst->cntSrcWin += src->cntSrcWin;
  dst->srcWinSize += src->srcWinSize;
  dst->cntDstWin += src->cntDstWin;
  dst->dstWinSize += src->dstWinSize;
  dst->cntSrcZeroWin += src->cntSrcZeroWin;
  dst->cntDstZeroWin += src->cntDstZeroWin;
  dst->cntLoadDelay += src->cntLoadDelay;
  dst->loadDelayUsec += src->loadDelayUsec;
  dst->sendBytes += src->sendBytes;
  dst->rcvdBytes += src->rcvdBytes;
}

void exportCommpairData(time_t tcurr)
{
  int i, j;
  CommPairHashNodeT *pnode;
  CommMsgT *pCommMsg;

  for(i = 0; i < COMMPAIR_HASH_SIZE; i++){
    pnode = pHashTable->node + i;
    for(j = 0; j < COMMPAIR_HASH_LENGTH; j++){
      pCommMsg = pnode->commpair + j;
      if(pCommMsg->appType == 0)
        continue;
      exportData(pCommMsg, tcurr);
      pCommMsg->appType = 0;
    }
  }
}

void exportCommpairData6(time_t tcurr)
{
  int i, j;
  CommPairHashNode6T *pnode;
  CommMsg6T *pCommMsg;

  for(i = 0; i < COMMPAIR_HASH_SIZE; i++){
    pnode = pHashTable6->node + i;
    for(j = 0; j < COMMPAIR_HASH_LENGTH; j++){
      pCommMsg = pnode->commpair + j;
      if(pCommMsg->appType == 0)
        continue;
      exportData6(pCommMsg, tcurr);
      pCommMsg->appType = 0;
    }
  }
}
