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
#include "http.h"
#include "db.h"
#include "session.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

void processHttpReq(NetSessionT *pNetSession, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession);
void processDbReq(NetSessionT *pNetSession, u_int32_t seq, int type, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession);

void processBusiness(NetSessionT *pNetSession, u_int32_t seq, int type, int direction, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession)
{
  int v;

  oneSession->valid = 0;
  if(direction == DIRECTION_CLI2SER){
    if(type == TYPE_HTTP)
      processHttpReq(pNetSession, ts, payload, payloadLen, oneSession); //process http request, get url, http version
    if((type == TYPE_ORACLE) || (type == TYPE_MYSQL) || (type == TYPE_SQLSERVER))
      processDbReq(pNetSession, seq, type, ts, payload, payloadLen, oneSession);//process database request, get sql
    memcpy(&(pNetSession->lastReqTime), ts, sizeof(struct timeval));
  }
  if(direction == DIRECTION_SER2CLI){
    if(pNetSession->lastDirection == DIRECTION_CLI2SER){
      if(type == TYPE_ORACLE)
        getOracleCode(&(pNetSession->busi.db.retcode), pNetSession->busi.db.errMess, payload, payloadLen);
      if(type == TYPE_MYSQL)
        getMysqlCode(&(pNetSession->busi.db.retcode), pNetSession->busi.db.errMess, payload, payloadLen);
      if(type == TYPE_SQLSERVER){
        getSqlserverCode(&(pNetSession->busi.db.retcode), pNetSession->busi.db.errMess, payload, payloadLen);
        getSqlServerUser(pNetSession->busi.db.user, pNetSession->busi.db.dbname, payload, payloadLen);
      }
    }
    if(type == TYPE_HTTP){
      v = timevalDiffUsec(ts, &(pNetSession->lastReqTime));
      if(pNetSession->lastDirection == DIRECTION_CLI2SER)
        pNetSession->busi.http.response = v;
      pNetSession->busi.http.pageload = v;
      if((pNetSession->busi.http.retcode >= 600) || (pNetSession->busi.http.retcode < 200)){
        v = isResStart((char*)payload, payloadLen, &(pNetSession->busi.http.retcode));
      }
    }
    if(type == TYPE_HTTP)
      pNetSession->resp = 1;
    if(type == TYPE_ORACLE)
      pNetSession->resp = 1;
    if(type == TYPE_MYSQL)
      pNetSession->resp = 1;
    if(type == TYPE_SQLSERVER)
      pNetSession->resp = 1;
  }
  if(type == TYPE_HTTP)
    memcpy(&(pNetSession->busi.http.endTime), ts, sizeof(struct timeval));
  if(type == TYPE_ORACLE)
    memcpy(&(pNetSession->busi.db.endTime), ts, sizeof(struct timeval));
  if(type == TYPE_MYSQL)
    memcpy(&(pNetSession->busi.db.endTime), ts, sizeof(struct timeval));
  if(type == TYPE_SQLSERVER)
    memcpy(&(pNetSession->busi.db.endTime), ts, sizeof(struct timeval));
  pNetSession->lastDirection = direction;
}

void processHttpReq(NetSessionT *pNetSession, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession)
{
  char url[MAX_URL_LENGTH], method[8], domain[64], contentType[128], agent[128];

  oneSession->valid = 0;
  if((pNetSession->lastDirection == DIRECTION_SER2CLI) && (pNetSession->busi.http.retcode != 100)){
    memcpy(oneSession, pNetSession, sizeof(NetSessionT));
    oneSession->valid = 1;
    resetSession(TYPE_HTTP, pNetSession);
  }
  url[0] = 0;
  method[0] = 0;
  domain[0] = 0;
  contentType[0] = 0;
  agent[0] = 0;
  if(isReqStart((char*)payload, payloadLen, url, method, domain, contentType, agent)){
    if(oneSession->valid == 0){
      memcpy(oneSession, pNetSession, sizeof(NetSessionT));
      oneSession->valid = 1;
      resetSession(TYPE_HTTP, pNetSession);
    }
    strcpy(pNetSession->busi.http.url, url);
    strcpy(pNetSession->busi.http.method, method);
    strcpy(pNetSession->busi.http.domain, domain);
    strcpy(pNetSession->busi.http.contentType, contentType);
    strcpy(pNetSession->busi.http.agent, agent);
    memcpy(&(pNetSession->busi.http.beginTime), ts, sizeof(struct timeval));
    getForward((char*)payload, payloadLen, &(pNetSession->forward));
    pNetSession->busi.http.pageload = 0;
    pNetSession->busi.http.response = 0;
  }
  if(pNetSession->busi.http.retcode != 100)
    memcpy(&(pNetSession->lastReqTime), ts, sizeof(struct timeval));
}

void processDbReq(NetSessionT *pNetSession, u_int32_t seq, int type, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession)
{
  int real;
  char sql[MAX_SQL_LENGTH];

  if((type == TYPE_ORACLE) && (payload[4] == 1)){
    if(getOracleUser(pNetSession->busi.db.user, payload, payloadLen))
      return;
  }
  real = 0;
  sql[0] = 0;
  if((type == TYPE_ORACLE) || (type == TYPE_MYSQL))
    getStrSql(sql, payload, payloadLen, &real);
  if(type == TYPE_SQLSERVER)
    getSqlserverSql(sql, payload, payloadLen, &real);
  if(sql[0] != 0){
    if(pNetSession->busi.db.real){
      pNetSession->busi.db.response = timevalDiffUsec(&(pNetSession->busi.db.endTime), &(pNetSession->busi.db.beginTime));
      memcpy(oneSession, pNetSession, sizeof(NetSessionT));
      oneSession->valid = 1;
      resetSession(type, pNetSession);
    }
    resetSession(type, pNetSession);
    strncpy(pNetSession->busi.db.sql, sql, MAX_SQL_LENGTH - 1);
    pNetSession->busi.db.sql[MAX_SQL_LENGTH - 1] = 0;
    pNetSession->resp = 0;
    pNetSession->busi.db.real = real;
    memcpy(&(pNetSession->busi.db.beginTime), ts, sizeof(struct timeval));
  }
}
