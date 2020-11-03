#ifndef _BUSINESS_H_
#define _BUSINESS_H_

void processBusiness(NetSessionT *pNetSession, u_int32_t seq, int type, int direction, const struct timeval *ts, const u_char *payload, int payloadLen, NetSessionT *oneSession);

#endif
