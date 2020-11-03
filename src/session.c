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

extern ReadOnlyGlobalT readOnlyGlobal;

void initSession(NetSessionT *pNetSession, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport);

NetSessionT* findSession(HashNodeT *pHashNode, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport, time_t tstamp, int *direction, NetSessionT *oneSession)
{  // Find session data according to hash algorithm
  int i, ind, find;
  NetSessionT *pNetSession;

  ind = -1;
  find = 0;
  pNetSession = 0;
  *direction = 0;
  for(i = 0; i < DEFAULT_HASH_LENGTH; i++){
    pNetSession = pHashNode->session + i;
    if(pNetSession->valid == 0){
      if(ind < 0)
        ind = i;
      continue;
    }
    if((proto == pNetSession->proto) && (src == pNetSession->src) && (sport == pNetSession->sport) && (dst == pNetSession->dst) && (dport == pNetSession->dport)){
      find = 1;
      *direction = DIRECTION_SRC2DST;
      break;
    }
    if((proto == pNetSession->proto) && (dst == pNetSession->src) && (dport == pNetSession->sport) && (src == pNetSession->dst) && (sport == pNetSession->dport)){
      find = 1;
      *direction = DIRECTION_DST2SRC;
      break;
    }
    if((ind < 0) && (pNetSession->state >= FLAG_STATE_FIN1_ACK0) && (tstamp - pNetSession->lastPktTime.tv_sec >= 2)){
      memcpy(oneSession, pNetSession, sizeof(NetSessionT));
      pNetSession->valid = 0;
      ind = i;
    }
  }
  if(find)
    return pNetSession;
  if(ind < 0)
    return 0;
  pNetSession = pHashNode->session + ind;
  initSession(pNetSession, vid, proto, src, dst, sport, dport);
  return pNetSession;
}

void initSession(NetSessionT *pNetSession, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport)
{  // Clear session information
  int backward;

  backward = 0;
  if(sport < dport)
    backward = 1;
  pNetSession->vid = vid;
  pNetSession->ver = 4;
  pNetSession->valid = 1;
  pNetSession->state = 0;
  pNetSession->src = src;
  pNetSession->dst = dst;
  pNetSession->bytes = 0;
  pNetSession->reqSeq = 0;
  pNetSession->resSeq = 0;
  pNetSession->reqLen = 0;
  pNetSession->resLen = 0;
  pNetSession->reqAckSeq = 0;
  pNetSession->resAckSeq = 0;
  pNetSession->sport = sport;
  pNetSession->dport = dport;
  pNetSession->proto = proto;
  pNetSession->lastDirection = 0;
  pNetSession->realDirection = 0;
  pNetSession->lastPktDirection = 0;
  pNetSession->reqTime.tv_sec = 0;
  pNetSession->reqTime.tv_usec = 0;
  pNetSession->lastPktTime.tv_sec = 0;
  pNetSession->lastPktTime.tv_usec = 0;
  pNetSession->lastPktDirectionTime.tv_sec = 0;
  pNetSession->lastPktDirectionTime.tv_usec = 0;
  pNetSession->firstResTime.tv_sec = 0;
  pNetSession->firstResTime.tv_usec = 0;
  pNetSession->resTime.tv_sec = 0;
  pNetSession->resTime.tv_usec = 0;
  if(backward){
    pNetSession->src = dst;
    pNetSession->dst = src;
    pNetSession->sport = dport;
    pNetSession->dport = sport;
  }
  pNetSession->busi.http.url[0] = 0;
  pNetSession->busi.http.beginTime.tv_sec = 0;
  clearSessionValue(pNetSession);
}

void resetSession(int type, NetSessionT *pNetSession) // Clear session business information
{
  pNetSession->forward = 0;
  pNetSession->bytes = 0;
  pNetSession->lastDirection = 0;
  memset(&(pNetSession->lastReqTime), 0x00, sizeof(struct timeval));
  if(type == TYPE_HTTP){
    pNetSession->busi.http.retcode = 0;
    pNetSession->busi.http.response = 0;
    pNetSession->busi.http.pageload = 0;
    memset(pNetSession->busi.http.url, 0x00, MAX_URL_LENGTH);
    memset(pNetSession->busi.http.method, 0x00, 8);
    memset(pNetSession->busi.http.domain, 0x00, 32);
    memset(pNetSession->busi.http.agent, 0x00, 64);
    memset(pNetSession->busi.http.contentType, 0x00, 64);
    memset(&(pNetSession->busi.http.beginTime), 0x00, sizeof(struct timeval));
    memset(&(pNetSession->busi.http.endTime), 0x00, sizeof(struct timeval));
    return;
  }
  pNetSession->busi.db.retcode = 0;
  pNetSession->busi.db.response = 0;
  pNetSession->busi.db.real = 0;
  memset(pNetSession->busi.db.sql, 0x00, MAX_SQL_LENGTH);
  memset(pNetSession->busi.db.errMess, 0x00, 128);
  memset(pNetSession->busi.db.user, 0x00, 32);
  memset(pNetSession->busi.db.dbname, 0x00, 32);
  memset(&(pNetSession->busi.db.beginTime), 0x00, sizeof(struct timeval));
  memset(&(pNetSession->busi.db.endTime), 0x00, sizeof(struct timeval));
}
