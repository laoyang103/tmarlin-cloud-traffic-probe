#ifndef _COMM_DEFINE_H_
#define _COMM_DEFINE_H_

#include <time.h>

#define COMM_TYPE_COMM           1
#define COMM_TYPE_HTTP           2
#define COMM_TYPE_ARP            3
#define COMM_TYPE_ORACLE         4
#define COMM_TYPE_MYSQL          5
#define COMM_TYPE_SQLSERVER      6
#define COMM_TYPE_CUSTOM         7
#define COMM_TYPE_DNS            8
#define COMM_TYPE_BGP            9
#define COMM_TYPE_SINGLE         10
#define COMM_TYPE_COMMV6         11
#define COMM_TYPE_SINGLEV6       12
#define COMM_TYPE_END            99
#define COMM_TYPE_SRC            1
#define COMM_TYPE_DST            2

typedef struct {
  u_int32_t type, appType;
  time_t time;
  u_char macSrc[6], macDst[6];
  u_int32_t did, lid, vid, src, dst, proto, sport, dport;
  u_int32_t sendPkts, rcvdPkts, sendTinyPkts, rcvdTinyPkts;
  u_int32_t srcConDelayUsec, dstConDelayUsec, cntSrcDelay;
  u_int32_t srcDelayUsec, srcRetransDelayUsec, cntDstDelay;
  u_int32_t dstDelayUsec, dstRetransDelayUsec, connNum;
  u_int32_t sendSynPkts, rcvdSynPkts, sendSynAckPkts;
  u_int32_t rcvdSynAckPkts, sendRstPkts, rcvdRstPkts; 
  u_int32_t sendFinPkts, rcvdFinPkts, sendRetransmitPkts;
  u_int32_t rcvdRetransmitPkts, cntCustomDelay;
  u_int32_t customDelayUsec, upTo64, upTo128, upTo256;
  u_int32_t upTo512, upTo1024, upTo1514, largePkts;
  u_int32_t cntSrcWin, srcWinSize, cntDstWin, dstWinSize;
  u_int32_t cntSrcZeroWin, cntDstZeroWin, realDirection;
  u_int32_t cntLoadDelay, loadDelayUsec;
  u_int64_t sendBytes, rcvdBytes;
#ifdef PROCESS_FLOW
  int pid, mem;
  double cpu;
  char process[16];
#endif
} CommMsgT;

typedef struct {
  u_int32_t type, appType;
  time_t time;
  u_char macSrc[6], macDst[6];
  u_char src[16], dst[16];
  u_int32_t did, lid, vid, proto, sport, dport;
  u_int32_t sendPkts, rcvdPkts, sendTinyPkts, rcvdTinyPkts;
  u_int32_t srcConDelayUsec, dstConDelayUsec, cntSrcDelay;
  u_int32_t srcDelayUsec, srcRetransDelayUsec, cntDstDelay;
  u_int32_t dstDelayUsec, dstRetransDelayUsec, connNum;
  u_int32_t sendSynPkts, rcvdSynPkts, sendSynAckPkts;
  u_int32_t rcvdSynAckPkts, sendRstPkts, rcvdRstPkts; 
  u_int32_t sendFinPkts, rcvdFinPkts, sendRetransmitPkts;
  u_int32_t rcvdRetransmitPkts, cntCustomDelay;
  u_int32_t customDelayUsec, upTo64, upTo128, upTo256;
  u_int32_t upTo512, upTo1024, upTo1514, largePkts;
  u_int32_t cntSrcWin, srcWinSize, cntDstWin, dstWinSize;
  u_int32_t cntSrcZeroWin, cntDstZeroWin, realDirection;
  u_int32_t cntLoadDelay, loadDelayUsec;
  u_int64_t sendBytes, rcvdBytes;
#ifdef PROCESS_FLOW
  int pid, mem;
  double cpu;
  char process[16];
#endif
} CommMsg6T;

typedef struct {
  u_int32_t type;
  time_t time;
  u_int32_t did, lid, vid, src, dst, proto, sport, dport;
  u_int32_t srcConDelayUsec, dstConDelayUsec, cntSrcDelay;
  u_int32_t srcDelayUsec, cntDstDelay, dstDelayUsec;
  u_int32_t responseUsec, responseCnt, pageloadUsec;
  u_int32_t pageloadCnt, cnt400, cnt500, l7Count, noResp;
} BssMsgT;

typedef struct {
  u_int32_t type;
  time_t time;
  u_char src[16], dst[16];
  u_int32_t did, lid, vid, proto, sport, dport;
  u_int32_t srcConDelayUsec, dstConDelayUsec, cntSrcDelay;
  u_int32_t srcDelayUsec, cntDstDelay, dstDelayUsec;
  u_int32_t responseUsec, responseCnt, pageloadUsec;
  u_int32_t pageloadCnt, cnt400, cnt500, l7Count, noResp;
} BssMsg6T;

#endif

