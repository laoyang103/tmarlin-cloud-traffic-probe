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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "util.h"
#include "session.h"
#include "data.h"
#include "business.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

void process6(u_char *macSrc, u_char *macDst, int vid, int proto, u_char *src, u_char *dst, int sport, int dport, u_int32_t seq, u_int32_t ackSeq, u_int8_t tcpFlag, const struct pcap_pkthdr *h, const u_char *payload, int payloadLen, int winSize, CommMsg6T *pCommMsg);
extern void processFirstPacket(NetSessionT *pNetSession, int proto, u_int32_t seq, u_int32_t ackSeq, const struct pcap_pkthdr *h, u_int8_t tcpFlag, int tiny, int direction, int payloadLen, int winSize);
extern void processStateAndAck(NetSessionT *pNetSession, int direction, u_int32_t seq, u_int32_t ackSeq, const struct timeval *ts, u_int8_t tcpFlag);
extern void processPayload(NetSessionT *pNetSession, int direction, u_int32_t seq, const struct timeval *ts, u_int8_t tcpFlag, int payloadLen, int *retran);

void processPacket6(const struct pcap_pkthdr *h, const u_char *sp, int *discard)
{
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  const u_char *payload, *spV6;
  CommMsg6T commMsg;
  u_int8_t tcpFlag;
  u_char macSrc[6], macDst[6];
  u_char srcV6[16], dstV6[16];
  int sport, dport, shift, totalLen;
  int ipLen, vid, proto, tcpLen;
  int payloadLen, winSize;
  u_int32_t seq, ackSeq;

  if(readOnlyGlobal.cntHost > 0){
    *discard = 1;
    return;
  }
  shift = 0;
  vid = 0;
  commMsg.sendPkts = 0;
  commMsg.rcvdPkts = 0;
  sport = 0;
  dport = 0;
  memcpy(macSrc, sp, 6);
  memcpy(macDst, sp+6, 6);
  if((sp[12] == 0x81) && (sp[13] == 0x00)){
    vid = sp[14] % 16 * 256 + sp[15];
    shift = 4;
    if((sp[16] == 0x81) && (sp[17] == 0x00))
      shift = 8;
  }
  if((sp[12 + shift] != 0x86) || (sp[13 + shift] != 0xdd)){
    *discard = 1;
    return;
  }
  spV6 = sp + shift + 14;
  proto = spV6[6];
  totalLen = h->caplen - shift - 14;
  if((proto != 6) && (proto != 17) && (proto != 1)){
    *discard = 1;
    return;
  }
  memcpy(srcV6, spV6+8, 16);
  memcpy(dstV6, spV6+24, 16);
  ipLen = 40;
  if(proto == 6){
    tcp = (struct tcphdr*)(sp + shift + 14 + ipLen);
    tcpFlag = sp[shift + 14 + ipLen + 13];
    sport = ntohs(tcp->source);
    dport = ntohs(tcp->dest);
    tcpLen = sp[shift + 14 + ipLen + 12] / 16;
    tcpLen *= 4;
    seq = ntohl(tcp->seq);
    ackSeq = ntohl(tcp->ack_seq);
    shift += 14 + ipLen + tcpLen;
    payload = sp + shift;
    payloadLen = totalLen - ipLen - tcpLen;
    if((payloadLen == 1) && (payload[0] == 0))
      payloadLen = 0;
    winSize = ntohs(tcp->window);
  }
  if(proto == 17){
    udp = (struct udphdr*)(sp + 14 + shift + ipLen);
    sport = ntohs(udp->source);
    dport = ntohs(udp->dest);
    shift = 14 + shift + ipLen + sizeof(struct udphdr);
    payloadLen = h->caplen - shift;
    payload = sp + shift;
    if(payloadLen <= 0){
      payloadLen = 0;
      payload = 0;
    }
  }
  if(proto == 1){
    shift = 14 + shift + ipLen;
    payload = sp + shift;
    payloadLen = h->caplen - shift;
  }
  process6(macSrc, macDst, vid, proto, srcV6, dstV6, sport, dport, seq, ackSeq, tcpFlag, h, payload, payloadLen, winSize, &commMsg);
  if((commMsg.sendPkts + commMsg.rcvdPkts) > 0)
    exportData6(&commMsg, globalValue.currTime);
}

void process6(u_char *macSrc, u_char *macDst, int vid, int proto, u_char *srcV6, u_char *dstV6, int sport, int dport, u_int32_t seq, u_int32_t ackSeq, u_int8_t tcpFlag, const struct pcap_pkthdr *h, const u_char *payload, int payloadLen, int winSize, CommMsg6T *pCommMsg)
{
  int tiny, bytes, rst, type;
  int direction, retran;
  u_int32_t src, dst, hashcode;
  HashNodeT *pHashNode;
  NetSessionT *pNetSession, oneSession, oneSession2;

  if(payloadLen <= 0)
    tiny = 1;
  if(tcpFlag & TH_RST)
    rst = 1;
  bytes = h->len;
  memcpy(&src, srcV6+12, 4);
  memcpy(&dst, dstV6+12, 4);
  hashcode = getHashCode(src, dst, sport, dport);
  pHashNode = globalValue.hashTable->node + hashcode;
  pthread_mutex_lock(&(pHashNode->mutex));
  pNetSession = findSession(pHashNode, vid, proto, src, dst, sport, dport, h->ts.tv_sec, &direction, &oneSession2);  // Find session data according to hash algorithm
  if(!pNetSession){
    pthread_mutex_unlock(&(pHashNode->mutex));
    return;
  }
  type = pNetSession->type;
  if((type == 0) && (proto == 6)){
    if(readOnlyGlobal.configInfo.autoCheck && (payloadLen > 0) && payload){
      type = checkAppType(payload, payloadLen);
    }
  }
  pNetSession->type = type;
  if(pNetSession->ver == 4){
    memcpy(pNetSession->srcV6, srcV6, 16);
    memcpy(pNetSession->dstV6, dstV6, 16);
    pNetSession->sport = sport;
    pNetSession->dport = dport;
    memcpy(pNetSession->macSrc, macSrc, 6);
    memcpy(pNetSession->macDst, macDst, 6);
    pNetSession->ver = 6;
  }
  if(direction == 0){
    if(tcpFlag == (TH_SYN | TH_ACK)){
      memcpy(pNetSession->dstV6, srcV6, 16);
      memcpy(pNetSession->srcV6, dstV6, 16);
      pNetSession->dport = sport;
      pNetSession->sport = dport;
      memcpy(pNetSession->macSrc, macDst, 6);
      memcpy(pNetSession->macDst, macSrc, 6);
      pNetSession->realDirection = 1;
    }
    if(tcpFlag == TH_SYN){
      memcpy(pNetSession->srcV6, srcV6, 16);
      memcpy(pNetSession->dstV6, dstV6, 16);
      pNetSession->dport = dport;
      pNetSession->sport = sport;
      memcpy(pNetSession->macSrc, macSrc, 6);
      memcpy(pNetSession->macDst, macDst, 6);
      pNetSession->realDirection = 1;
    }
    if(((tcpFlag & TH_SYN) == 0) && (sport < dport)){
      memcpy(pNetSession->dstV6, srcV6, 16);
      memcpy(pNetSession->srcV6, dstV6, 16);
      pNetSession->dport = sport;
      pNetSession->sport = dport;
      memcpy(pNetSession->macSrc, macDst, 6);
      memcpy(pNetSession->macDst, macSrc, 6);
    }
    direction = DIRECTION_SRC2DST;
    if(pNetSession->src == dst)
      direction = DIRECTION_DST2SRC;
    processFirstPacket(pNetSession, proto, seq, ackSeq, h, tcpFlag, tiny, direction, payloadLen, winSize);
    pthread_mutex_unlock(&(pHashNode->mutex));
    if(oneSession2.valid){
      cloneMsgValue6(pCommMsg, &oneSession2);
      exportBusinessData(&oneSession2);
    }
    return;
  }else{
    if(tcpFlag == TH_SYN){
      pNetSession->reqSeq = 0;
      pNetSession->resSeq = 0;
      pNetSession->reqLen = 0;
      pNetSession->resLen = 0;
      pNetSession->reqAckSeq = 0;
      pNetSession->resAckSeq = 0;
    }
  }
  processStateAndAck(pNetSession, direction, seq, ackSeq, &(h->ts), tcpFlag);
  retran = 0;
  if(payloadLen > 0)
    processPayload(pNetSession, direction, seq, &(h->ts), tcpFlag, payloadLen, &retran);
  if(retran == 0){
    if(payloadLen > 0)
      processBusiness(pNetSession, seq, type, direction, &(h->ts), payload, payloadLen, &oneSession);
    pNetSession->bytes += h->len;
  }

  if(direction == DIRECTION_SRC2DST){
    pNetSession->rcvdPkts++;
    pNetSession->rcvdBytes += bytes;
    pNetSession->rcvdTinyPkts += tiny;
    pNetSession->rcvdRstPkts += rst;
    if(proto == 6){
      pNetSession->reqLen = payloadLen;
      pNetSession->reqSeq = seq;
      if(winSize == 0)
        pNetSession->cntSrcZeroWin++;
    }
  }
  if(direction == DIRECTION_DST2SRC){
    pNetSession->sendPkts++;
    pNetSession->sendBytes += bytes;
    pNetSession->sendTinyPkts += tiny;
    pNetSession->sendRstPkts += rst;
    if(proto == 6){
      pNetSession->resLen = payloadLen;
      pNetSession->resSeq = seq;
      if(winSize == 0)
        pNetSession->cntDstZeroWin++;
    }
  }

  pNetSession->lastPktTime.tv_sec = h->ts.tv_sec;
  pNetSession->lastPktTime.tv_usec = h->ts.tv_usec;
  pNetSession->lastPktDirection = direction;
  addSessionDistribute(pNetSession, bytes);
  pthread_mutex_unlock(&(pHashNode->mutex));
  if(oneSession.valid)
    exportBusinessData(&oneSession);
  if(oneSession2.valid){
    cloneMsgValue6(pCommMsg, &oneSession2);
    exportBusinessData(&oneSession2);
  }
  if(retran){
    pthread_mutex_lock(&(globalValue.processState.mutex));
    globalValue.processState.retran++;
    pthread_mutex_unlock(&(globalValue.processState.mutex));
  }
  return;
}
