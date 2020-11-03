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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "util.h"
#include "data.h"
#include "session.h"
#include "process6.h"
#include "business.h"

#define OFFSETMASK 0x1FFF
#define TH_FIN     0x01
#define TH_SYN     0x02
#define TH_RST     0x04
#define TH_PUSH    0x08
#define TH_ACK     0x10

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

void processGRE(int vid, const struct pcap_pkthdr *h, const u_char *sp, int len, CommMsgT *pCommMsg, int *discard);
void processVxLan(int vid, const struct pcap_pkthdr *h, const u_char *sp, int len, CommMsgT *pCommMsg, int *discard);
void process(u_char *macSrc, u_char *macDst, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport, u_int32_t seq, u_int32_t ackSeq, u_int8_t tcpFlag, const struct pcap_pkthdr *h, u_short frag, const u_char *payload, int payloadLen, int winSize, CommMsgT *pCommMsg);
void processFirstPacket(NetSessionT *pNetSession, int proto, u_int32_t seq, u_int32_t ackSeq, const struct pcap_pkthdr *h, u_int8_t tcpFlag, int tiny, int direction, int payloadLen, int winSize);
void processStateAndAck(NetSessionT *pNetSession, int direction, u_int32_t seq, u_int32_t ackSeq, const struct timeval *ts, u_int8_t tcpFlag);
void processPayload(NetSessionT *pNetSession, int direction, u_int32_t seq, const struct timeval *ts, u_int8_t tcpFlag, int payloadLen, int *retran);
int isRepeat(NetSessionT *pNetSession, int direction, u_short frag);
void processIcmp(NetSessionT *pNetSession, u_int32_t src, u_int32_t dst, const struct pcap_pkthdr *h, const u_char *payload, int payloadLen);
int checkAppType(const u_char *payload, int payloadLen);

void processPacket(const struct pcap_pkthdr *h, const u_char *sp, int *discard)
{
  const struct ip *sip;
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  u_int32_t src, dst, seq, ackSeq;
  u_int8_t tcpFlag;
  u_short frag;
  const u_char *payload;
  u_char macSrc[6], macDst[6];
  int sport, dport, shift, totalLen;
  int ind, offset, ipLen, proto;
  int payloadLen, tcpLen, vid, winSize;
  CommMsgT commMsg;

  shift = 0;
  vid = 0;
  tcpFlag = 0;
  ackSeq = 0;
  seq = 0;
  winSize = 0;
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
  if((sp[12 + shift] == 0x86) || (sp[13 + shift] == 0xdd)){ // Check whether is V6 packet
    processPacket6(h, sp, discard);
    return;
  }
  if((sp[12 + shift] != 0x08) || (sp[13 + shift] != 0x00)){  // Give up packet
    *discard = 1;
    return;
  }
  sip = (struct ip*)(sp + shift + 14);
  proto = sip->ip_p;
  totalLen = ntohs(sip->ip_len);
  if(proto == 47){  // Process gre packet
    ipLen = sp[14 + shift] % 16;
    ipLen *= 4;
    shift += ipLen + 14;
    if((sp[shift + 2] == 0x65) && (sp[shift + 3] == 0x58))
      shift += 18;
    if((sp[shift + 2] == 0x08) && (sp[shift + 3] == 0x00))
      shift += 4;
    if((sp[shift + 2] == 0x88) && (sp[shift + 3] == 0x0b)){
      if(sp[shift + 1] == 0x81)
        shift += 17;
      else
        shift += 13;
    }
    src = ntohl(sip->ip_src.s_addr);
    dst = ntohl(sip->ip_dst.s_addr);
    if(readOnlyGlobal.isPktExp && (dst == readOnlyGlobal.expPktNumIP)){
      *discard = 1;  // Packets sent by itself
      return;
    }
    payload = sp + shift;
    payloadLen = h->caplen - shift;
    processGRE(vid, h, payload, payloadLen, &commMsg, discard);
    if((commMsg.sendPkts + commMsg.rcvdPkts) > 0)
      exportData(&commMsg, globalValue.currTime);
    return;
  }
  if((proto != 6) && (proto != 17) && (proto != 1)){
    *discard = 1;
    return;
  }
  frag = ntohs(sip->ip_id);
  offset = ntohs(sip->ip_off) & OFFSETMASK;
  src = ntohl(sip->ip_src.s_addr);
  dst = ntohl(sip->ip_dst.s_addr);
  if(readOnlyGlobal.isPktExp){  // Packets sent by itself
    if(dst == readOnlyGlobal.expPktNumIP)
      *discard = 1;
    if(proto == 6)
      *discard = 0;
    if(*discard == 1)
      return;
  }
  ipLen = sp[14 + shift] % 16;
  ipLen *= 4;
  if(proto == 6){
    tcp = (struct tcphdr*)(sp + shift + 14 + ipLen + offset);
    tcpFlag = sp[shift + 14 + ipLen + offset + 13];
    sport = ntohs(tcp->source);
    dport = ntohs(tcp->dest);
    tcpLen = sp[shift + 14 + ipLen + offset + 12] / 16;
    tcpLen *= 4;
    seq = ntohl(tcp->seq);
    ackSeq = ntohl(tcp->ack_seq);
    shift += 14 + ipLen + offset + tcpLen;
    payload = sp + shift;
    payloadLen = totalLen - ipLen - tcpLen - offset;
    if((payloadLen == 1) && (payload[0] == 0))
      payloadLen = 0;
    winSize = ntohs(tcp->window);
  }
  if(proto == 17){
    udp = (struct udphdr*)(sp + 14 + shift + ipLen + offset);
    sport = ntohs(udp->source);
    dport = ntohs(udp->dest);
    if((dst == readOnlyGlobal.expNumIP) && (dport == readOnlyGlobal.configInfo.expPort)){  // Packets sent by itself
      *discard = 1;
      return;
    }
    if((dst == readOnlyGlobal.expPktNumIP) && (dport == readOnlyGlobal.expPktPort)){  // Packets sent by itself
      *discard = 1;
      return;
    }
    shift = 14 + shift + ipLen + offset + sizeof(struct udphdr);
    payloadLen = h->caplen - shift;
    payload = sp + shift;
    if(payloadLen <= 0){
      payloadLen = 0;
      payload = 0;
    }
    if((payloadLen > 0) && (payload[0] == 0x08) && (payload[1] == 0x00)){
      payload += 8;
      payloadLen -= 8;
      processVxLan(vid, h, payload, payloadLen, &commMsg, discard);  // Process Vxlan packet
      return;
    }
  }
  if(proto == 1){
    shift = 14 + shift + ipLen + offset;
    payload = sp + shift;
    payloadLen = h->caplen - shift;
  }
  ind = 0;
  if(readOnlyGlobal.cntHost > 0){
    ind = findServer(src, sport, proto);
    if(ind < 0)
      ind = findServer(dst, dport, proto);
  }
  if(ind < 0){  //  Don't deal with this packet
    *discard = 1;
    return;
  }
  process(macSrc, macDst, vid, proto, src, dst, sport, dport, seq, ackSeq, tcpFlag, h, frag, payload, payloadLen, winSize, &commMsg);
  if((commMsg.sendPkts + commMsg.rcvdPkts) > 0) // Send occupied session directly
    exportData(&commMsg, globalValue.currTime);
}

void processVxLan(int vid, const struct pcap_pkthdr *h, const u_char *sp, int len, CommMsgT *pCommMsg, int *discard)  // Process Vxlan packet
{
  const struct ip *sip;
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  u_int32_t src, dst, seq, ackSeq;
  u_int8_t tcpFlag;
  u_char macSrc[6], macDst[6];
  int sport, dport, shift, winSize;
  int offset, ipLen, proto, totalLen;
  int payloadLen, tcpLen, frag, ind;
  const u_char *payload;
  CommMsgT commMsg;

  shift = 0;
  sport = 0;
  dport = 0;
  memcpy(macSrc, sp, 6);
  memcpy(macDst, sp+6, 6);
  if((sp[12] == 0x81) && (sp[13] == 0x00)){
    shift = 4;
    if((sp[16] == 0x81) && (sp[17] == 0x00))
      shift = 8;
  }
  if((sp[12] == 0x88) && (sp[13] == 0x47)){
    shift = 4;
    if((sp[16] & 0x01) == 0)
      shift = 8;
  }
  sip = (struct ip*)(sp + shift + 14);
  proto = sip->ip_p;
  src = ntohl(sip->ip_src.s_addr);
  dst = ntohl(sip->ip_dst.s_addr);
  if((proto != 6) && (proto != 17) && (proto != 1)){
    *discard = 1;
    return;
  }
  totalLen = ntohs(sip->ip_len);
  frag = ntohs(sip->ip_id);
  offset = ntohs(sip->ip_off) & OFFSETMASK;
  ipLen = sp[14 + shift] % 16;
  ipLen *= 4;
  winSize = 0;
  if(proto == 1){
    payload = sp + shift + 14 + 20;
    payloadLen = len - shift - 14 - 20;
  }
  if(proto == 6){
    tcp = (struct tcphdr*)(sp + shift + 14 + ipLen + offset);
    tcpFlag = sp[shift + 14 + ipLen + offset + 13];
    sport = ntohs(tcp->source);
    dport = ntohs(tcp->dest);
    tcpLen = sp[shift + 14 + ipLen + offset + 12] / 16;
    tcpLen *= 4;
    seq = ntohl(tcp->seq);
    ackSeq = ntohl(tcp->ack_seq);
    shift += 14 + ipLen + offset + tcpLen;
    payload = sp + shift;
    payloadLen = totalLen - ipLen - tcpLen - offset;
    if(payloadLen <= 0){
      payloadLen = 0;
    }
    winSize = ntohs(tcp->window);
  }
  if(proto == 17){
    udp = (struct udphdr*)(sp + 14 + shift + ipLen + offset);
    sport = ntohs(udp->source);
    dport = ntohs(udp->dest);
    shift = 14 + shift + ipLen + offset + sizeof(struct udphdr);
    payload = sp + shift;
    payloadLen = h->caplen - shift;
    if(payloadLen <= 0){
      payloadLen = 0;
    }
  }
  ind = 0;
  if(readOnlyGlobal.cntHost > 0){
    ind = findServer(src, sport, proto);
    if(ind < 0)
      ind = findServer(dst, dport, proto);
  }
  if(ind < 0){
    *discard = 1;
    return;
  }

  process(macSrc, macDst, vid, proto, src, dst, sport, dport, seq, ackSeq, tcpFlag, h, frag, payload, payloadLen, winSize, &commMsg);
  if((commMsg.sendPkts + commMsg.rcvdPkts) > 0)
    exportData(&commMsg, globalValue.currTime);
}

void processGRE(int vid, const struct pcap_pkthdr *h, const u_char *sp, int len, CommMsgT *pCommMsg, int *discard)  // Process gre packet
{
  const struct ip *sip;
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  u_int32_t src, dst, seq, ackSeq;
  u_int8_t tcpFlag;
  u_char macSrc[6], macDst[6];
  int sport, dport, shift, winSize;
  int offset, ipLen, proto, frag, tmpLen;
  int payloadLen, tcpLen, ind;
  const u_char *payload, *tmpsp;

  sip = (struct ip*)sp;
  tmpsp = sp;
  tmpLen = len;
  proto = sip->ip_p;
  shift = 0;
  ipLen = sp[0] % 16;
  ipLen *= 4;
  sport = 0;
  dport = 0;
  memset(macSrc, 0x00, 6);
  memset(macDst, 0x00, 6);
  if(proto == 47){
    shift = ipLen;
    if((sp[shift + 2] == 0x65) && (sp[shift + 3] == 0x58))
      shift += 18;
    if((sp[shift + 2] == 0x08) && (sp[shift + 3] == 0x00))
      shift += 4;
    if((sp[shift + 2] == 0x88) && (sp[shift + 3] == 0x0b)){
      if(sp[shift + 1] == 0x81)
        shift += 17;
      else
        shift += 13;
    }
    tmpsp = sp + shift;
    tmpLen = h->caplen - shift;
    sip = (struct ip*)tmpsp;
    proto = sip->ip_p;
    ipLen = tmpsp[0] % 16;
    ipLen *= 4;
  }
  if((proto != 6) && (proto != 17)){
    *discard = 1;
    return;
  }
  shift = ipLen;
  frag = ntohs(sip->ip_id);
  offset = ntohs(sip->ip_off) & OFFSETMASK;
  src = ntohl(sip->ip_src.s_addr);
  dst = ntohl(sip->ip_dst.s_addr);
  winSize = 0;
  if(proto == 6){
    tcp = (struct tcphdr*)(tmpsp + shift + offset);
    tcpFlag = tmpsp[shift + offset + 13];
    sport = ntohs(tcp->source);
    dport = ntohs(tcp->dest);
    tcpLen = tmpsp[shift + offset + 12] / 16;
    tcpLen *= 4;
    seq = ntohl(tcp->seq);
    ackSeq = ntohl(tcp->ack_seq);
    shift += offset + tcpLen;
    payload = tmpsp + shift;
    payloadLen = tmpLen - shift;
    if((payloadLen <= 6) && (len <= 66) && (payload[0] == 0))
      payloadLen = 0;
    winSize = ntohs(tcp->window);
  }
  if(proto == 17){
    udp = (struct udphdr*)(tmpsp + shift + offset);
    sport = ntohs(udp->source);
    dport = ntohs(udp->dest);
    shift += offset + sizeof(struct udphdr);
    payloadLen = tmpLen - shift;
    payload = tmpsp + shift;
    if(payloadLen <= 0){
      payloadLen = 0;
      payload = 0;
    }
  }
  ind = 0;
  if(readOnlyGlobal.cntHost > 0){
    ind = findServer(src, sport, proto);
    if(ind < 0)
      ind = findServer(dst, dport, proto);
  }
  if(ind < 0){
    *discard = 1;
    return;
  }
  process(macSrc, macDst, vid, proto, src, dst, sport, dport, seq, ackSeq, tcpFlag, h, frag, payload, payloadLen, winSize, pCommMsg);
}

void process(u_char *macSrc, u_char *macDst, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport, u_int32_t seq, u_int32_t ackSeq, u_int8_t tcpFlag, const struct pcap_pkthdr *h, u_short frag, const u_char *payload, int payloadLen, int winSize, CommMsgT *pCommMsg)
{
  HashNodeT *pHashNode;
  NetSessionT *pNetSession, oneSession, oneSession2;
  u_int32_t hashcode;
  int tiny, bytes, direction, rst, retran, type, ind;

  tiny = 0;
  bytes = h->len;
  rst = 0;
  type = 0;
  oneSession.valid = 0;
  oneSession2.valid = 0;
  if(payloadLen <= 0)
    tiny = 1;
  if(tcpFlag & TH_RST)
    rst = 1;
  ind = findServer(src, sport, proto);
  if(ind < 0)
    ind = findServer(dst, dport, proto);
  if(ind >= 0)
    type = readOnlyGlobal.hostInfo[ind].type;
  hashcode = getHashCode(src, dst, sport, dport);
  pHashNode = globalValue.hashTable->node + hashcode;
  pthread_mutex_lock(&(pHashNode->mutex));
  pNetSession = findSession(pHashNode, vid, proto, src, dst, sport, dport, h->ts.tv_sec, &direction, &oneSession2);  // Find session data according to hash algorithm
  if(!pNetSession){
    pthread_mutex_unlock(&(pHashNode->mutex));
    return;
  }
  if(type == 0)
    type = pNetSession->type;
  if((type == 0) && (proto == 6)){
    if(readOnlyGlobal.configInfo.autoCheck && (payloadLen > 0) && payload){
      type = checkAppType(payload, payloadLen);
    }
  }

  if(proto == 1){
    processIcmp(pNetSession, src, dst, h, payload, payloadLen);
  }
  pNetSession->type = type;
  if(direction == 0){
    if(tcpFlag == (TH_SYN | TH_ACK)){
      pNetSession->dst = src;
      pNetSession->src = dst;
      pNetSession->dport = sport;
      pNetSession->sport = dport;
      pNetSession->realDirection = 1;
      memcpy(pNetSession->macSrc, macDst, 6);
      memcpy(pNetSession->macDst, macSrc, 6);
    }
    if(tcpFlag == TH_SYN){
      pNetSession->dst = dst;
      pNetSession->src = src;
      pNetSession->dport = dport;
      pNetSession->sport = sport;
      pNetSession->realDirection = 1;
      memcpy(pNetSession->macSrc, macSrc, 6);
      memcpy(pNetSession->macDst, macDst, 6);
    }
    if(((tcpFlag & TH_SYN) == 0) && (sport < dport)){
      pNetSession->dst = src;
      pNetSession->src = dst;
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
      cloneMsgValue(pCommMsg, &oneSession2);
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

  if(readOnlyGlobal.disableRepeat && isRepeat(pNetSession, direction, frag) && (frag != 0)){
    pthread_mutex_unlock(&(pHashNode->mutex));
    return;
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
    cloneMsgValue(pCommMsg, &oneSession2);
    exportBusinessData(&oneSession2);
  }
  if(retran){
    pthread_mutex_lock(&(globalValue.processState.mutex));
    globalValue.processState.retran++;
    pthread_mutex_unlock(&(globalValue.processState.mutex));
  }
  return;
}

void processFirstPacket(NetSessionT *pNetSession, int proto, u_int32_t seq, u_int32_t ackSeq, const struct pcap_pkthdr *h, u_int8_t tcpFlag, int tiny, int direction, int payloadLen, int winSize)
{ // Process the first packet of the session
  int bytes, syn, rst, fin, synAck;

  bytes = h->len;
  rst = 0;
  syn = 0;
  fin = 0;
  synAck = 0;
  if(tcpFlag & TH_RST)
    rst = 1;
  if((tcpFlag & TH_SYN) && ((tcpFlag & TH_ACK) == 0))
    syn = 1;
  if(tcpFlag == (TH_SYN|TH_ACK))
    synAck = 1;
  if(tcpFlag & TH_FIN)
    fin = 1;
  pNetSession->state = FLAG_STATE_ACTIVE;
  if(tcpFlag == TH_SYN)
    pNetSession->state = FLAG_STATE_SYN;
  if(tcpFlag == (TH_SYN | TH_ACK))
    pNetSession->state = FLAG_STATE_SYN_ACK;
  if(tcpFlag & TH_FIN)
    pNetSession->state = FLAG_STATE_FIN1_ACK0;
  if(direction == DIRECTION_SRC2DST){
    pNetSession->rcvdPkts++;
    pNetSession->rcvdBytes += bytes;
    pNetSession->rcvdTinyPkts += tiny;
    pNetSession->rcvdSynPkts += syn;
    pNetSession->rcvdSynAckPkts += synAck;
    pNetSession->rcvdRstPkts += rst;
    if(fin)
      pNetSession->sendFinPkts = COMM_TYPE_SRC;
    pNetSession->reqSeq = seq;
    pNetSession->reqAckSeq = ackSeq;
    pNetSession->reqLen = payloadLen;
    if((winSize == 0) && (proto == 6))
      pNetSession->cntSrcZeroWin++;
  }
  if(direction == DIRECTION_DST2SRC){
    pNetSession->sendPkts++;
    pNetSession->sendBytes += bytes;
    pNetSession->sendTinyPkts += tiny;
    pNetSession->sendSynPkts += syn;
    pNetSession->sendSynAckPkts += synAck;
    pNetSession->sendRstPkts += rst;
    if(fin)
      pNetSession->sendFinPkts = COMM_TYPE_DST;
    pNetSession->resSeq = seq;
    pNetSession->resAckSeq = ackSeq;
    pNetSession->resLen = payloadLen;
    if((winSize == 0) && (proto == 6))
        pNetSession->cntDstZeroWin++;
  }
  pNetSession->lastPktDirection = direction;
  pNetSession->lastPktTime.tv_sec = h->ts.tv_sec;
  pNetSession->lastPktTime.tv_usec = h->ts.tv_usec;
  pNetSession->lastPktDirectionTime.tv_sec = h->ts.tv_sec;
  pNetSession->lastPktDirectionTime.tv_usec = h->ts.tv_usec;
  addSessionDistribute(pNetSession, bytes);
}

void processStateAndAck(NetSessionT *pNetSession, int direction, u_int32_t seq, u_int32_t ackSeq, const struct timeval *ts, u_int8_t tcpFlag)
{  // Process TCP state
  int v1, v2;

  if(pNetSession->proto != 6)
    return;
  if((tcpFlag & TH_SYN) && ((tcpFlag & TH_ACK) == 0)){
    pNetSession->rcvdSynPkts += 1;
    pNetSession->state = FLAG_STATE_SYN;
    return;
  }
  if(tcpFlag == (TH_SYN | TH_ACK))
    pNetSession->sendSynAckPkts += 1;
  if(tcpFlag & TH_FIN){
    if(pNetSession->state <= FLAG_STATE_ACTIVE){
      pNetSession->state = FLAG_STATE_FIN1_ACK0;
      if(direction == DIRECTION_SRC2DST)
        pNetSession->sendFinPkts = COMM_TYPE_SRC;
      if(direction == DIRECTION_DST2SRC)
        pNetSession->sendFinPkts = COMM_TYPE_DST;
    }else{
      pNetSession->state = FLAG_STATE_FIN2_ACK0;
      if(direction == DIRECTION_SRC2DST)
        pNetSession->rcvdFinPkts = COMM_TYPE_SRC;
      if(direction == DIRECTION_DST2SRC)
        pNetSession->rcvdFinPkts = COMM_TYPE_DST;
    }
    return;
  }
  if(direction == 0)
    return;
  if((tcpFlag == (TH_SYN | TH_ACK)) && (pNetSession->state == FLAG_STATE_SYN)){
    pNetSession->serConDelayUsec = timevalDiffUsec(ts, &(pNetSession->lastPktTime));  // Get the server handshake delay
    if(pNetSession->serConDelayUsec > MAX_TIMEVAL_DELAY_DIFF)
      pNetSession->serConDelayUsec = 0;
    pNetSession->state = FLAG_STATE_SYN_ACK;
    pNetSession->resSeq = seq;
    return;
  }
  if((tcpFlag == TH_ACK) && (pNetSession->state == FLAG_STATE_SYN_ACK)){
    pNetSession->state = FLAG_STATE_ACTIVE;
    pNetSession->cliConDelayUsec = timevalDiffUsec(ts, &(pNetSession->lastPktTime));  // Get the client handshake delay
    if(pNetSession->cliConDelayUsec > MAX_TIMEVAL_DELAY_DIFF)
      pNetSession->cliConDelayUsec = 0;
    pNetSession->connNum += 1;
    pNetSession->reqSeq = seq;
    return;
  }
  if(tcpFlag & TH_RST)
    return;

  if(direction != pNetSession->lastPktDirection){
    if(direction == DIRECTION_SRC2DST){
      if(pNetSession->reqAckSeq >= ackSeq)
        return;
      if(ackSeq > pNetSession->resSeq){
        if((direction != pNetSession->lastDirection) && (pNetSession->resLen > 0)){
          v1 = timevalDiffUsec(ts, &(pNetSession->lastPktTime));
          if(v1 > MAX_TIMEVAL_DELAY_DIFF)
            v1 = 0;
          v2 = timevalDiffUsec(&(pNetSession->lastPktTime), &(pNetSession->lastPktDirectionTime));
          if(v2 > MAX_TIMEVAL_DELAY_DIFF)
            v2 = 0;
          if(v2 < v1)
            v2 = v1;
          pNetSession->cliDelayUsec += v1;  // Calculate client latency
          pNetSession->cliRetransDelayUsec += v2;
          if((v1 > 0) || (v2 > 0))
            pNetSession->cntCliDelay++;
        }
        pNetSession->reqAckSeq = ackSeq;
      }
    }
    if(direction == DIRECTION_DST2SRC){
      if(pNetSession->resAckSeq >= ackSeq)
        return;
      if(ackSeq > pNetSession->reqSeq){
        if((direction != pNetSession->lastDirection) && (pNetSession->reqLen > 0)){
          v1 = timevalDiffUsec(ts, &(pNetSession->lastPktTime));
          if(v1 > MAX_TIMEVAL_DELAY_DIFF)
            v1 = 0;
          v2 = timevalDiffUsec(&(pNetSession->lastPktTime), &(pNetSession->lastPktDirectionTime));
          if(v2 > MAX_TIMEVAL_DELAY_DIFF)
            v2 = 0;
          if(v2 < v1)
            v2 = v1;
          pNetSession->serDelayUsec += v1;  // Calculate server latency
          pNetSession->serRetransDelayUsec += v2;
          if((v1 > 0) || (v2 > 0))
            pNetSession->cntSerDelay++;
        }
        pNetSession->resAckSeq = ackSeq;
      }
    }
  }
}
void processPayload(NetSessionT *pNetSession, int direction, u_int32_t seq, const struct timeval *ts, u_int8_t tcpFlag, int payloadLen, int *retran)
{ //  Processing load segments of packet data
  int v, isRestran;

  isRestran = 0;
  if(direction == 0)
    return;
  if(direction == DIRECTION_SRC2DST){
    if((seq < pNetSession->reqSeq) && (payloadLen > 1)){
      if(pNetSession->proto == 6){
        pNetSession->rcvdRetransmitPkts++;
        isRestran = 1;
        *retran = 1;
      }
    }
    if((seq == pNetSession->reqSeq) && (payloadLen == pNetSession->reqLen) && (payloadLen > 1)){
      if(pNetSession->proto == 6){  // is repeat
        pNetSession->rcvdRetransmitPkts++;
        isRestran = 1;
        *retran = 1;
      }
    }
    pNetSession->reqSeq = seq;
    pNetSession->reqTime = *ts;
    if(pNetSession->lastDirection == DIRECTION_DST2SRC){
      if(pNetSession->proto == 6){
        v = timevalDiffUsec(&(pNetSession->resTime), &(pNetSession->firstResTime));  // Get load delay using first response time
        if(v > MAX_TIMEVAL_DIFF)
          v = 0;
        if(v > 0){
          pNetSession->cntLoadDelay++;
          pNetSession->loadDelayUsec += v;
        }
      }
    }
  }
  if(direction == DIRECTION_DST2SRC){
    if((seq < pNetSession->resSeq) && (payloadLen > 1)){
      if(pNetSession->proto == 6){
        pNetSession->sendRetransmitPkts++;
        isRestran = 1;
        *retran = 1;
      }
    }
    if((seq == pNetSession->resSeq) && (payloadLen == pNetSession->resLen) && (payloadLen > 1)){
      if(pNetSession->proto == 6){
        pNetSession->sendRetransmitPkts++;
        isRestran = 1;
        *retran = 1;
      }
    }
    pNetSession->resSeq = seq;
    if(pNetSession->lastDirection == DIRECTION_SRC2DST){
      v = timevalDiffUsec(ts, &(pNetSession->reqTime));  // Get response delay using request time
      if(v > MAX_TIMEVAL_DIFF)
        v = 0;
      if(v > 0){
        pNetSession->customDelayUsec += v;
        pNetSession->cntCustomDelay++;
      }
      pNetSession->firstResTime = *ts;
    }
    pNetSession->resTime = *ts;
  }
  if(isRestran == 0){
    pNetSession->lastPktDirectionTime.tv_sec = ts->tv_sec;
    pNetSession->lastPktDirectionTime.tv_usec = ts->tv_usec;
  }
  pNetSession->lastDirection = direction;
}

int isRepeat(NetSessionT *pNetSession, int direction, u_short frag)  // Check whether is a duplicate packet
{
  int i, ind;

  if(direction == DIRECTION_SRC2DST){
    ind = pNetSession->fragInd1;
    if(ind > 3){
      ind = 3;
      pNetSession->fragInd1 = ind;
    }
    for(i = 0; i < 4; i++){
      if(ind < 0)
        ind = 3;
      if(frag == pNetSession->srcFragID[ind])
        return 1;
      ind--;
    }
    ind = pNetSession->fragInd1 + 1;
    if(ind > 3)
      ind = 0;
    pNetSession->srcFragID[ind] = frag;
    pNetSession->fragInd1 = ind;
    return 0;
  }
  ind = pNetSession->fragInd2;
  if(ind > 3){
    ind = 3;
    pNetSession->fragInd2 = ind;
  }
  for(i = 0; i < 4; i++){
    if(ind < 0)
      ind = 3;
    if(frag == pNetSession->dstFragID[ind])
      return 1;
    ind--;
  }
  ind = pNetSession->fragInd2 + 1;
  if(ind > 3)
    ind = 0;
  pNetSession->dstFragID[ind] = frag;
  pNetSession->fragInd2 = ind;
  return 0;
}

void processIcmp(NetSessionT *pNetSession, u_int32_t src, u_int32_t dst, const struct pcap_pkthdr *h, const u_char *payload, int payloadLen)  // Process icmp packet
{
  int v;
  u_int32_t seq, uv;

  v = timevalDiffUsec(&(h->ts), &(pNetSession->lastPktTime));
  if(payload == 0)
    return;
  if(payloadLen < 8)
    return;
  seq = payload[6] * 256 + payload[7];
  if(pNetSession->forward == 0){
    pNetSession->forward = seq;
    pNetSession->lastPktTime.tv_sec = h->ts.tv_sec;
    pNetSession->lastPktTime.tv_usec = h->ts.tv_usec;
    return;
  }
  if((src == pNetSession->src) && (seq == pNetSession->forward)){
    uv = pNetSession->src;
    pNetSession->src = pNetSession->dst;
    pNetSession->dst = uv;
    pNetSession->customDelayUsec = 0;
    pNetSession->cntCustomDelay = 0;
    pNetSession->reqSeq = seq;
  }
  if((src == pNetSession->dst) && (seq == pNetSession->forward)){
    pNetSession->resSeq = seq;
    pNetSession->customDelayUsec = v;
    pNetSession->cntCustomDelay = 1;
  }
  pNetSession->forward = seq;
  pNetSession->lastPktTime.tv_sec = h->ts.tv_sec;
  pNetSession->lastPktTime.tv_usec = h->ts.tv_usec;
}
