#ifndef _DB_H_
#define _DB_H_

#include "util.h"

void getStrSql(char *sql, const u_char *payload, int payloadLen, int *real);
void getSqlserverSql(char *sql, const u_char *payload, int payloadLen, int *real);
void getOracleCode(int *code, char *errMess, const u_char *payload, int payloadLen);
void getMysqlCode(int *code, char *errMess, const u_char *payload, int payloadLen);
void getSqlserverCode(int *code, char *errMess, const u_char *payload, int payloadLen);
int getOracleUser(char *user, const u_char *payload, int payloadLen);
int getSqlServerUser(char *user, char *dbname, const u_char *payload, int payloadLen);

#endif
