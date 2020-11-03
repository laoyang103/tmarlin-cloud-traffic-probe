#ifndef _SESSION_H_
#define _SESSION_H_

NetSessionT* findSession(HashNodeT *pHashNode, int vid, int proto, u_int32_t src, u_int32_t dst, int sport, int dport, time_t tstamp, int *direction, NetSessionT *oneSession);
void resetSession(int type, NetSessionT *pNetSession);

#endif
