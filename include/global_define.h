#ifndef _GLOBAL_DEFINE_H_
#define _GLOBAL_DEFINE_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include "comm.h"

#define  TYPE_HTTP                           1
#define  TYPE_ORACLE                         2
#define  TYPE_MYSQL                          3
#define  TYPE_SQLSERVER                      4

#define  DIRECTION_CLI2SER                   1
#define  DIRECTION_SER2CLI                   2

#define  FLAG_STATE_SYN                      1
#define  FLAG_STATE_SYN_ACK                  2
#define  FLAG_STATE_ACTIVE                   3
#define  FLAG_STATE_FIN1_ACK0                4
#define  FLAG_STATE_FIN2_ACK0                5

#define  RUN_MODE_DISPLAY                    1
#define  COMM_TYPE_COMM                      1
#define  DIRECTION_SRC2DST                   1
#define  DIRECTION_DST2SRC                   2
#define  MAX_PACKET_COUNT                    4
#define  DEFAULT_REFRESH_INTERVAL            10
#define  MAX_SESSION_COUNT                   20
#define  DEFAULT_TOP_SESSION                 20
#define  DEFAULT_HASH_LENGTH                 16
#define  MAX_FILTER_COUNT                    16
#define  DEFAULT_TIME_OUT                    30
#define  DEFAULT_SESSION_TIMEOUT             60
#define  DEFAULT_JSON_SPACE                  10
#define  DEFAULT_PKTS_SPACE                  50
#define  MAX_FILE_COUNT                      100
#define  MAX_URL_LENGTH                      256
#define  MAX_COMM_VALUE                      1024
#define  MAX_SQL_LENGTH                      1024
#define  DEFAULT_HASH_SIZE                   2048
#define  MAX_TIMEVAL_DELAY_DIFF              5000000
#define  MAX_TIMEVAL_DIFF                    60000000
#define  DEFAULT_DATABASE_NAME               "ipm"
#define  DEFAULT_FILE_PREFIX                 "jft"
#define  MAX_POSTLINE                        2048
#define  MAX_DEVICE                          128

#define  VP_CHK_MAX_PKT_DROP                 5.0
#define  VP_CHK_MAX_CPU_USAGE                20
#define  VP_CHK_MAX_MEM_USAGE                5
#define  VP_CHK_PORT                         80
#define  VP_CHK_VERSION_KEY                  "svn version:"
#define  VP_CHK_DID_KEY                      ":did:"
#define  VP_CHK_LICENSE_RUN_KEY              ":run:"
#define  VP_CHK_LICENSE_DATE_KEY             ":valid:"
#define  VP_CHK_LOG_DIR                      "/var/log/vprobe/"
#define  VP_CHK_VERSION_URL                  "/cgi-bin/getVProbeVersion.cgi"
#define  VP_CHK_BIN_URL                      "/cgi-bin/getVProbeBinary.cgi"
#define  VP_CHK_DID_URL                      "/cgi-bin/addVPWatchPoint.cgi"
#define  VP_CHK_LICENSE_URL                  "/cgi-bin/addVPWatchPoint.cgi"
#define  VP_CHK_USER_URL                     "/user/chkVPUser.do"
#define  VP_CHK_DOMAIN_CN                    "vpm.51alert.cn"
#define  VP_CHK_DOMAIN_US                    "vpm.tcpiplabs.com"
#define  VP_CHK_NO_DOLPHIN_KEY               "NoDolphin"
#define  VP_CONFIG_PATH                      "/etc/jsonflow.conf"
#define  VP_RUNLIMIT_PATH                    "/etc/jsonflow.runlimit"
#define  VP_RUNLIMIT_KEY                     0xB4D285C1      

typedef enum _vp_app_type {
  VP_APP_TCP = 12,
  VP_APP_HTTP = 4,
  VP_APP_ORACLE = 5,
  VP_APP_MYSQL = 6,
  VP_APP_SQLSERVER = 7
} VP_APP_TYPE;

typedef struct {
  char dev[64];
  u_int32_t addr;
} DevInfoT;

typedef struct {
  char hostStr[32];
  u_int32_t addressLow, addressHigh;
  int port, type, proto;
} HostInfoT;

typedef struct _http_session {
  int retcode, response, pageload;
  struct timeval beginTime, endTime;
  char url[MAX_URL_LENGTH], method[8];
  char contentType[64], agent[64];
  char domain[32];
} HttpSessionT;

typedef struct _db_session {
  int retcode, response, real;
  struct timeval beginTime, endTime;
  char sql[MAX_SQL_LENGTH], errMess[128];
  char user[32], dbname[32];
} DbSessionT;

typedef struct _net_session {
  int did, lid, vid, valid, state, bytes, type;
  u_int32_t src, dst, reqSeq, resSeq, ver;
  u_int32_t reqAckSeq, resAckSeq, forward;
  u_char macSrc[6], macDst[6];
  u_char srcV6[16], dstV6[16];
  int sport, dport, resp;
  int proto, lastPktDirection, reqLen, resLen;
  int lastDirection, realDirection, fragInd1, fragInd2;
  u_short srcFragID[4], dstFragID[4];
  struct timeval lastPktTime, reqTime, lastPktDirectionTime;
  struct timeval firstResTime, resTime, lastReqTime;
  u_int64_t sendBytes, rcvdBytes;
  u_int32_t sendPkts, rcvdPkts, sendTinyPkts, rcvdTinyPkts;
  u_int32_t cliConDelayUsec, cntCliDelay, cliDelayUsec;
  u_int32_t serConDelayUsec, cntSerDelay, serDelayUsec;
  u_int32_t cliRetransDelayUsec, serRetransDelayUsec;
  u_int32_t sendSynPkts, rcvdSynPkts, sendSynAckPkts;
  u_int32_t rcvdSynAckPkts, sendRstPkts, rcvdRstPkts;
  u_int32_t sendFinPkts, rcvdFinPkts, sendRetransmitPkts;
  u_int32_t rcvdRetransmitPkts, cntCustomDelay;
  u_int32_t customDelayUsec, connNum, cntSrcWin, srcWinSize;
  u_int32_t cntDstWin, dstWinSize, upTo64, upTo128, upTo256;
  u_int32_t upTo512, upTo1024, upTo1514, largePkts;
  u_int32_t cntSrcZeroWin, cntDstZeroWin;
  u_int32_t cntLoadDelay, loadDelayUsec;
  union{
    HttpSessionT http;
    DbSessionT db;
  } busi;
} NetSessionT;

typedef struct {
  NetSessionT session[DEFAULT_HASH_LENGTH];
  pthread_mutex_t mutex;
} HashNodeT;

typedef struct {
  HashNodeT node[DEFAULT_HASH_SIZE];
} HashTableT;

typedef struct _ptcs_pkthdr {
  u_int32_t tv_sec, tv_usec;
  u_int32_t caplen, len;
} ptcs_pkthdr;

typedef enum _top_session_field {
  TOP_FIELD_SOURCE,
  TOP_FIELD_DESTINATION,
  TOP_FIELD_PROTO,
#ifdef PROCESS_FLOW
  TOP_FIELD_PROGRAM,
  TOP_FIELD_CPU,
  TOP_FIELD_MEM,
#endif
  TOP_FIELD_TRAFFIC,
  TOP_FIELD_PACKETS,
  TOP_FIELD_PKTLOSE,
  TOP_FIELD_RTTDELAY,
  TOP_FIELD_SYNDELAY,
  TOP_FIELD_RESPDELAY,
  TOP_FIELD_LOADDELAY
} TopSessionField;

typedef struct _topSessionNode {
  NetSessionT *sessionPtr;
  struct _topSessionNode *prev, *next;
} TopSessionNode;

typedef struct {
  char localDir[128], prefix[64];
  int fileSize, fileCount, currSize, currInd;
  time_t tLast;
  FILE *fp;
} StoreInfoT;

typedef struct {
  int jsonSize, pcapSize, expPort, maxLength;
  int pcapFileSize, autoCheck;
  char username[32], password[32];
  char dolphin[32], devName[32];
  char jsonPath[32], pcapPath[32];
  char expDomain[32], expPktDomain[32];
} ConfigInfoT;

typedef struct {
  int did, cntHost, disableRepeat, isExp, isChk, licenseRun;
  int isLogin, isPktExp, expPktPort, runFlag, loadFlag;
  int sessionTimeOut, enablePkts, enableJson, chkPort;
  time_t licenseValid;
  u_char mac[6];
  char sysVersion[32], devMac[32];
  char chkDomain[32], hostname[64], hostuser[64];
  struct sockaddr_in devAddress, chkAddress;
  struct sockaddr_in expAddress, expPktAddress;
  u_int32_t expNumIP, expPktNumIP, chkNumIP;
  u_int32_t isDolphin, runMode, pause;
  ConfigInfoT configInfo;
  HostInfoT hostInfo[64];
  char progName[32];
  FILE *runLimitFP;
} ReadOnlyGlobalT;

typedef struct {
  int byte, pkt, retran;
  pthread_mutex_t mutex;
} ProcessStateT;

typedef struct {
  u_int32_t src, dst;
  u_char ubuf[65536];
  u_int32_t packetID, vid;
  int valid, len, shift;
} PacketInfoT;

typedef struct {
  HashTableT *hashTable;
  time_t currTime, realCurrTime;
  int currYear, currMonth, currDay;
  ProcessStateT processState;
  int pcapDrop, pcapRecv, flushPkts;
  float gcpu, gmem; 
  StoreInfoT siPkts, siJson;
  PacketInfoT pInfo[MAX_PACKET_COUNT];
} GlobalValueT;

typedef struct {
  u_int32_t addressLow, addressHigh;
  int port;
} FilterInfoT;

typedef struct {
  time_t tstart, tend;
  char devName[64], filePath[256];
  char expPath[256], content[256];
  int cntFilter, isExp, isContent;
  FilterInfoT filters[16];
} DispReadOnlyGlobalT;

typedef struct _file_node{
  char filename[256];
  time_t lasttime;
  struct _file_node *prev, *next;
} FileNodeT;

typedef struct {
  time_t time;
  int sec;
  u_int32_t src, dst, proto, sport, dport;
  int bytes, pkt, lose, avgLen, tiny;
  int fin, rst, largePkt, zeroWin, syn;
  float rtt, synRtt, resp, load;
#ifdef PROCESS_FLOW
  int mem;
  float cpu;
  char process[16];
#endif
} CommValueT;

typedef struct {
  time_t time;
  int sec;
  u_char src[16], dst[16];
  u_int32_t proto, sport, dport;
  int bytes, pkt, lose, avgLen, tiny;
  int fin, rst, largePkt, zeroWin, syn;
  float rtt, synRtt, resp, load;
#ifdef PROCESS_FLOW
  int mem;
  float cpu;
  char process[16];
#endif
} CommValue6T;

typedef struct {
  time_t time;
  int type;
  u_int32_t src, dst, proto, sport, dport;
  int bytes, retcode, response, pageload;
  char beginTime[32], endTime[32];
  char url[256], domain[32], contentType[32];
  char agent[32], method[8];
#ifdef PROCESS_FLOW
  int mem;
  float cpu;
  char process[16];
#endif
} BssValueT;

typedef struct {
  int cntFile, cntValue;
  int cntValue6, cntBssValue;
  FILE *expFP;
  char filename[128];
  FileNodeT *pHead;
  CommValueT *pCommValue;
  CommValue6T *pCommValue6;
  BssValueT *pBssValue;
} DispGlobalValueT;

#endif
