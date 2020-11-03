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
#include "log.h"
#include "engine.h"
#include "ipm_version.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
extern pcap_t *caphandler;

static FILE *topfp;
static char pidStr[32];

int getPingOut(char *domain)
{
  char buf[1024], *p, tmp[1024];
  FILE *fp;
  int i, len, v;

  v = -1;
  sprintf(buf, "ping %s -w 3 2>&1", domain);
  fp = popen(buf, "r");
  if(fp == 0)
    return -1;
  while(1){
    p = fgets(buf, 1024, fp);
    if(p == 0)
      break;
    if(buf[0] == 0)
      break;
    toLowerCase(buf);
    p = strstr(buf, "ttl");
    if(p == 0)
      continue;
    p = strstr(buf, "time");
    if(p == 0)
      continue;
    p = p + 5;
    strcpy(tmp, p);
    len = strlen(tmp);
    for(i = 0; i < len; i++){
      if(tmp[i] == ' ')
        tmp[i] = 0;
      if(tmp[i] == '\r')
        tmp[i] = 0;
      if(tmp[i] == '\n')
        tmp[i] = 0;
      if(tmp[i] == '.')
        tmp[i] = 0;
    }
    v = atoi(tmp);
    pclose(fp);
    break;
  }
  return v;
}

int getLocalDomain()
{
  char buf1[256], buf2[256];
  int v1, v2, port1, port2;

  strcpy(buf1, VP_CHK_DOMAIN_US);
  strcpy(buf2, VP_CHK_DOMAIN_CN);
  port1 = VP_CHK_PORT;
  port2 = VP_CHK_PORT;
  v1 = getPingOut(buf1);  //Get the region by Ping the time of domain name
  v2 = getPingOut(buf2);
  if((v1 < 0) && (v2 < 0)) return 0;
  if(v1 < 0){
    strcpy(readOnlyGlobal.chkDomain, buf2);
    readOnlyGlobal.chkPort = port2;
    return 1;
  }
  if(v2 < 0){
    strcpy(readOnlyGlobal.chkDomain, buf1);
    readOnlyGlobal.chkPort = port1;
    return 1;
  }
  if(v1 > v2){
    strcpy(readOnlyGlobal.chkDomain, buf2);
    readOnlyGlobal.chkPort = port2;
    return 1;
  }
  strcpy(readOnlyGlobal.chkDomain, buf1);
  readOnlyGlobal.chkPort = port1;
  return 1;
}

int initCheck()
{
  int ret;
  char cmd[1024];

  sprintf(pidStr, "%d", getpid());
  sprintf(cmd, "top -b -p %s -d 5", pidStr);
  topfp = popen(cmd, "r");
  if (NULL == topfp) {
    writeLog(PROBE_LOG_ERROR, "can not create top fp");
  }
  if (getLocalDomain()) {
    readOnlyGlobal.isChk = 1; 
    ret = getDomainAddr(readOnlyGlobal.chkDomain, &readOnlyGlobal.chkAddress, 
        &readOnlyGlobal.chkNumIP, 80);
    if (-1 == ret) return 0;
    else return 1;
  } else {
    return 0;
  }
}

static int execUpdate(char *newver)
{
  int outlen;
  FILE *newfp;
  char newname[64]; 

  if(!readOnlyGlobal.isChk)
    return 0;
  sprintf(newname, "/tmp/tmarlin.%s", newver);
  newfp = fopen(newname, "w");
  if (NULL == newfp) {
    writeLog(PROBE_LOG_ERROR, "can not create %s update cancel ...", newname);
    return -1;
  }
  outlen = doPost(&readOnlyGlobal.chkAddress, VP_CHK_BIN_URL, "&sys=linux", NULL, newfp);
  if (0 == outlen) {
    writeLog(PROBE_LOG_ERROR, "can not get tmarlin bin, update cancel ...");
    return -1;
  }
  fclose(newfp);
  chmod(newname, S_IRWXU);
  writeLog(PROBE_LOG_MESSAGE, "The latest version %s has download to %s", newver, newname);
  return 0;
}

int chkVersion()
{
  int i, outlen;
  char output[4096], currver[64], lastver[64];

  if(!readOnlyGlobal.isChk)
    return 0;
  strcpy(currver, SVN_VERSION);

  outlen = doPost(&readOnlyGlobal.chkAddress, VP_CHK_VERSION_URL, "&sys=linux", output, NULL);
  output[outlen] = 0;
  if (0 == outlen || !strstr(output, VP_CHK_VERSION_KEY)) {
    writeLog(PROBE_LOG_WARNING, "check version failed %s", output);
    return -1;
  }
  output[outlen] = 0;
  for (i = outlen-1; i >= 0; i--) if (':' == output[i]) break;
  strcpy(lastver, output + i + 1);
  if (atoi(currver) < atoi(lastver)) {
    writeLog(PROBE_LOG_MESSAGE, "current version is %s, newest version is %s", currver, lastver);
    return execUpdate(lastver);
  } else {
    writeLog(PROBE_LOG_MESSAGE, "current version is %s, newest version is %s", currver, lastver);
  }
  return 0;
}

void getSelfUsage() // Get its own CPU and memory
{
  int fieldNum, topTry = 20;
  struct pcap_stat pcapStat;
  char *token, outbuf[MAX_POSTLINE];
  char topField[16][32];

  while (topTry-- && NULL != fgets(outbuf, MAX_POSTLINE, topfp)) {
    if (!strstr(outbuf, pidStr)) continue;
    fieldNum = 0;
    token = strtok(outbuf, " ");
    while (NULL != token) {
      strcpy(topField[fieldNum++], token);
      token = strtok(NULL, " ");
    }
    globalValue.gcpu = atof(topField[8]);
    globalValue.gmem = atof(topField[9]);
    break;
  }
  if (NULL != caphandler) {
    pcap_stats(caphandler, &pcapStat);                                                                               
    globalValue.pcapRecv = pcapStat.ps_recv;
    globalValue.pcapDrop = pcapStat.ps_drop+pcapStat.ps_ifdrop;
  }
}

int chkUser()
{
  size_t outlen;
  char output[4096];

  if(!readOnlyGlobal.isChk)
    return 0;
  if (0 ==  readOnlyGlobal.configInfo.username[0] || 0 ==  readOnlyGlobal.configInfo.password[0]) {
    writeLog(PROBE_LOG_WARNING, "Username and Password is empty or error, may affect the use of some functions");
    return 0;
  }
  outlen = doPost(&readOnlyGlobal.chkAddress, VP_CHK_USER_URL, "", output, NULL);
  output[outlen] = 0;
  if (0 == outlen) return -1;
  if (!strstr(output, readOnlyGlobal.configInfo.username)) {
    writeLog(PROBE_LOG_ERROR, "user %s not exist or password error", readOnlyGlobal.configInfo.username);
    return -1;
  }
  readOnlyGlobal.isLogin = 1;
  writeLog(PROBE_LOG_MESSAGE, "user %s authentication is successful", readOnlyGlobal.configInfo.username);
  readOnlyGlobal.isDolphin = 1;
  if (strstr(output, VP_CHK_NO_DOLPHIN_KEY)) {
    readOnlyGlobal.isDolphin = 0;
    writeLog(PROBE_LOG_ERROR, "user %s can not use Dolphin", readOnlyGlobal.configInfo.username);
    return -1;
  }
  return 0;
}

int chkNicDid(char *domain)
{
  size_t outlen;
  int ret;
  u_int32_t numIP;
  struct sockaddr_in addr;
  char *didstr, poststr[256], output[4096];

  ret = getDomainAddr(domain, &addr, &numIP, 80);
  if(ret < 0){
    writeLog(PROBE_LOG_ERROR, "Wrong domain %s\n", domain);
    return -1;
  }
  sprintf(poststr, "&ip=%s&mac=%s&host=%s&user=%s&email=%s&ver=2.0.%s",
      inet_ntoa(readOnlyGlobal.devAddress.sin_addr), readOnlyGlobal.devMac, 
      readOnlyGlobal.hostname, readOnlyGlobal.hostuser, readOnlyGlobal.configInfo.username, SVN_VERSION);
  outlen = doPost(&addr, VP_CHK_DID_URL, poststr, output, NULL);
  output[outlen] = 0;
  if (0 == outlen) return -1;
  if (NULL == (didstr = strstr(output, VP_CHK_DID_KEY))) {
    writeLog(PROBE_LOG_ERROR, "get nic %s did error %s", readOnlyGlobal.devMac, output);
    return -1;
  } else {
    readOnlyGlobal.did = atoi(didstr + strlen(VP_CHK_DID_KEY));
    writeLog(PROBE_LOG_MESSAGE, "nic %s did is %d\n", readOnlyGlobal.devMac, readOnlyGlobal.did);
  }
  return 0;
}

int chkLicense()
{
  size_t outlen;
  char *licstr, poststr[256], output[4096], errbuf[1024];

  sprintf(poststr, "&ip=%s&mac=%s&host=%s&user=%s&email=%s&password=%s&dolphin=%d&ver=2.0.%s",
		  inet_ntoa(readOnlyGlobal.devAddress.sin_addr), readOnlyGlobal.devMac,
		  readOnlyGlobal.hostname, readOnlyGlobal.hostuser, readOnlyGlobal.configInfo.username,
		  readOnlyGlobal.configInfo.password, readOnlyGlobal.isDolphin, 
		  SVN_VERSION);
  outlen = doPost(&readOnlyGlobal.chkAddress, VP_CHK_LICENSE_URL, poststr, output, NULL);
  if (-1 == outlen) return -1;
  if (0 == outlen) {
    strcpy(errbuf, "Server response is empty");
    return -1;
  }
  output[outlen] = 0;
  if (NULL == (licstr = strstr(output, VP_CHK_LICENSE_DATE_KEY))) {
    writeLog(PROBE_LOG_ERROR, "get license date key error %s", output);
    return -1;
  } else {
    readOnlyGlobal.licenseValid= atoi(licstr + strlen(VP_CHK_LICENSE_DATE_KEY));
    fseek(readOnlyGlobal.runLimitFP, 0, SEEK_SET); 
    fprintf(readOnlyGlobal.runLimitFP, "%u", (u_int32_t )readOnlyGlobal.licenseValid ^ VP_RUNLIMIT_KEY);
    fflush(readOnlyGlobal.runLimitFP);
  }
  if (NULL == (licstr = strstr(output, VP_CHK_LICENSE_RUN_KEY))) {
    writeLog(PROBE_LOG_ERROR, "get license run key error %s", output);
    return -1;
  } else {
    readOnlyGlobal.licenseRun = atoi(licstr + strlen(VP_CHK_LICENSE_RUN_KEY));
  }
  return 0;
}

int chkLocalLicense()
{
  u_int32_t runLimit;

  readOnlyGlobal.runLimitFP = fopen(VP_RUNLIMIT_PATH, "r+");
  if (NULL == readOnlyGlobal.runLimitFP) {
    readOnlyGlobal.runLimitFP = fopen(VP_RUNLIMIT_PATH, "w+");
    if (NULL == readOnlyGlobal.runLimitFP) {
      writeLog(PROBE_LOG_ERROR, "can not create runlimit file: %s", VP_RUNLIMIT_PATH);
      return -1;
    } else {
      readOnlyGlobal.licenseRun = 1;
      runLimit = time(NULL) + 604800;
      readOnlyGlobal.licenseValid = runLimit;
      fprintf(readOnlyGlobal.runLimitFP, "%u", runLimit ^ VP_RUNLIMIT_KEY);
      fflush(readOnlyGlobal.runLimitFP);
    }
  } else {
    fscanf(readOnlyGlobal.runLimitFP, "%u", &runLimit);
    runLimit ^= VP_RUNLIMIT_KEY;
    readOnlyGlobal.licenseValid = runLimit;
  }
  return 0;
}

