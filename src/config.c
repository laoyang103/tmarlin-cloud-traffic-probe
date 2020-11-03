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
#include "data.h"
#include "config.h"
#include "engine.h"
#include "cJSON.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
int serverfd;

void saveConfig(ConfigInfoT *pConfig);

void _trim(char *str)
{
  int len, i;
  char tmp[8192], *p;

  strcpy(tmp, str);
  len = strlen(tmp);
  p = 0;
  for(i = 0; i < len; i++){
    if(tmp[i] != ' '){
      p = tmp + i;
      break;
    }
  }
  if(p)
    strcpy(str, p);
  len = strlen(str);
  for(i = len - 1; i >= 0; i--){
    if((str[i] != ' ') && (str[i] != '\n') && (str[i] != '\r'))
      break;
    str[i] = 0;
  }
}

void loadAndSaveConfig()  //load and save configuration information from config file
{
  ConfigInfoT tmpConfigInfo, *pConfig;
  int port;

  pConfig = &(readOnlyGlobal.configInfo);
  memset(&tmpConfigInfo, 0x00, sizeof(ConfigInfoT));
  if(readOnlyGlobal.loadFlag){
    loadConfig(pConfig);
    if(pConfig->expPktDomain[0] != 0){
      if(!getDomainAddr(readOnlyGlobal.configInfo.expPktDomain, &readOnlyGlobal.expPktAddress, &readOnlyGlobal.expPktNumIP, 4789)){
        readOnlyGlobal.isPktExp = 1;
        readOnlyGlobal.expPktPort = 4789;
      }
    }
    if(pConfig->expDomain[0] != 0){
      port = 9015;
      if(pConfig->expPort != 0)
        port = pConfig->expPort;
      if(!getDomainAddr(readOnlyGlobal.configInfo.expDomain, &readOnlyGlobal.expAddress, &readOnlyGlobal.expNumIP, port)){
        readOnlyGlobal.isExp = 1;
      }
    }
    return;
  }
  loadConfig(&tmpConfigInfo);
  tmpConfigInfo.autoCheck = pConfig->autoCheck;
  if((tmpConfigInfo.username[0] == 0) && (pConfig->username[0] != 0))
    strcpy(tmpConfigInfo.username, pConfig->username);
  if((tmpConfigInfo.password[0] == 0) && (pConfig->password[0] != 0))
    strcpy(tmpConfigInfo.password, pConfig->password);
  if((tmpConfigInfo.dolphin[0] == 0) && (pConfig->dolphin[0] != 0))
    strcpy(tmpConfigInfo.dolphin, pConfig->dolphin);
  if((tmpConfigInfo.devName[0] == 0) && (pConfig->devName[0] != 0))
    strcpy(tmpConfigInfo.devName, pConfig->devName);
  if((tmpConfigInfo.jsonPath[0] == 0) && (pConfig->jsonPath[0] != 0))
    strcpy(tmpConfigInfo.jsonPath, pConfig->jsonPath);
  if((tmpConfigInfo.pcapPath[0] == 0) && (pConfig->pcapPath[0] != 0))
    strcpy(tmpConfigInfo.pcapPath, pConfig->pcapPath);
  if((tmpConfigInfo.expDomain[0] == 0) && (pConfig->expDomain[0] != 0))
    strcpy(tmpConfigInfo.expDomain, pConfig->expDomain);
  if((tmpConfigInfo.expPktDomain[0] == 0) && (pConfig->expPktDomain[0] != 0))
    strcpy(tmpConfigInfo.expPktDomain, pConfig->expPktDomain);
  if((tmpConfigInfo.jsonSize == 0) && (pConfig->jsonSize != 0))
    tmpConfigInfo.jsonSize = pConfig->jsonSize;
  if((tmpConfigInfo.pcapSize == 0) && (pConfig->pcapSize != 0))
    tmpConfigInfo.pcapSize = pConfig->pcapSize;
  if((tmpConfigInfo.expPort == 0) && (pConfig->expPort != 0))
    tmpConfigInfo.expPort = pConfig->expPort;
  if((tmpConfigInfo.maxLength == 0) && (pConfig->maxLength != 0))
    tmpConfigInfo.maxLength = pConfig->maxLength;
  if((tmpConfigInfo.pcapFileSize == 0) && (pConfig->pcapFileSize != 0))
    tmpConfigInfo.pcapFileSize = pConfig->pcapFileSize;
  saveConfig(&tmpConfigInfo);
}

int loadConfig(ConfigInfoT *pConfig)  //loading configuration information from config file
{
  FILE *fp;
  char *p, buf[1024], tmp[1024];

  fp = fopen(VP_CONFIG_PATH, "r");
  if(fp == 0)
    return -1;
  while(1){
    p = fgets(buf, 1024, fp);
    if(p == 0)
      break;
    if(buf[0] == 0)
      break;
    _trim(buf);
    p = strstr(buf, "=");
    if(p == 0)
      continue;
    p++;
    strcpy(tmp, p);
    trim(tmp);
    if(strstr(buf, "username"))
      strcpy(pConfig->username, tmp);
    if(strstr(buf, "password"))
      strcpy(pConfig->password, tmp);
    if(strstr(buf, "json-path"))
      strcpy(pConfig->jsonPath, tmp);
    if(strstr(buf, "pcap-path"))
      strcpy(pConfig->pcapPath, tmp);
    if(strstr(buf, "json-size"))
      pConfig->jsonSize = atoi(tmp);
    if(strstr(buf, "pcap-size"))
      pConfig->pcapSize = atoi(tmp);
    if(strstr(buf, "auto-check"))
      pConfig->autoCheck = atoi(tmp);
    if(strstr(buf, "device"))
      strcpy(pConfig->devName, tmp);
    if(strstr(buf, "dolphin"))
      strcpy(pConfig->dolphin, tmp);
    if(strstr(buf, "exp-domain"))
      strcpy(pConfig->expDomain, tmp);
    if(strstr(buf, "exp-port"))
      pConfig->expPort = atoi(tmp);
    if(strstr(buf, "max-length"))
      pConfig->maxLength = atoi(tmp);
    if(strstr(buf, "expPkt-domain"))
      strcpy(pConfig->expPktDomain, tmp);
    if(strstr(buf, "pcap-file-size"))
      pConfig->pcapFileSize = atoi(tmp);
  }
  fclose(fp);
  return 0;
}

void saveConfig(ConfigInfoT *pConfig)  //save configuration information
{
  FILE *fp;

  fp = fopen(VP_CONFIG_PATH, "w");
  if(fp == 0)
    return;
  fprintf(fp, "username=%s\n", pConfig->username);
  fprintf(fp, "password=%s\n", pConfig->password);
  fprintf(fp, "json-path=%s\n", pConfig->jsonPath);
  fprintf(fp, "pcap-path=%s\n", pConfig->pcapPath);
  fprintf(fp, "json-size=%d\n", pConfig->jsonSize);
  fprintf(fp, "pcap-size=%d\n", pConfig->pcapSize);
  fprintf(fp, "device=%s\n", pConfig->devName);
  fprintf(fp, "dolphin=%s\n", pConfig->dolphin);
  fprintf(fp, "exp-domain=%s\n", pConfig->expDomain);
  fprintf(fp, "exp-port=%d\n", pConfig->expPort);
  fprintf(fp, "max-length=%d\n", pConfig->maxLength);
  fprintf(fp, "expPkt-domain=%s\n", pConfig->expPktDomain);
  fprintf(fp, "auto-check=%d\n", pConfig->autoCheck);
  fprintf(fp, "pcap-file-size=%d\n", pConfig->pcapFileSize);
  fclose(fp);
  return;
}
