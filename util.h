#ifndef _UTIL_H_
#define _UTIL_H_

#include "global_define.h"

int initGlobalValue();
void trim(char *str);
void toLowerCase(char *str);
void toUpperCase(char *str);
time_t getGlobalTime(time_t tt);
int timevalDiffUsec(const struct timeval *end, const struct timeval *start);
void cloneMsgValue(CommMsgT *pCommMsg, NetSessionT *pNetSession);
void cloneMsgValue6(CommMsg6T *pCommMsg, NetSessionT *pNetSession);
void clearSessionValue(NetSessionT *pNetSession);
int findServer(u_int32_t addr, int port, int proto);
int getHashCode(u_int32_t src, u_int32_t dst, int sport, int dport);
void addSessionDistribute(NetSessionT *pNetSession, int len);
int getHostInfo(const char *str, HostInfoT *host);
int getIPFromStr(const char *str, u_int32_t *address);
float getRttFromSession(CommMsgT *pCommMsg);
float getRttFromSession6(CommMsg6T *pCommMsg);
float getConFromSession(CommMsgT *pCommMsg);
float getConFromSession6(CommMsg6T *pCommMsg);
float getPacketLose(CommMsgT *pCommMsg);
float getPacketLose6(CommMsg6T *pCommMsg);
float getDiv(float a, float b);
void getIPPortStrFromUint(unsigned int ip, int port, char *buf);
void getTraffic(float bytes, char *buf);
void getPkts(float pkts, char *buf);
void getCurrDate(int *year, int *month, int *day);
char* format_tv(struct timeval *a, char *buf, u_int buf_len);
int getCmdOutOneLine(char *cmd, char *outbuf, int outlen);
int doPost(struct sockaddr_in *addr, char *path, char *poststr, char *output, FILE *outfp);
int getDomainAddr(char *domain, struct sockaddr_in *addr, u_int32_t *IpNumPtr, u_int32_t port);
int checkHostStr(char *hostStr);
void setHostType(char *str, int ind);
int makeHeaderBuf(unsigned char *ubuf);
void getStrTime(time_t tt, char *str);
void getFileStrTime(time_t tt, char *str);
int chkDir(char *str);
int checkAppType(const u_char *payload, int payloadLen);
void getIPV6Str(u_char *ipV6, char *buf);
void getIPV6PortStrFromUint(u_char *ipV6, int port, char *buf);
void getStrMac(u_char *mac, char *buf);
int getUbyteIP6(char *str, u_char *addr);

#endif
