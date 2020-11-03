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
#include <sys/types.h>
#include <dirent.h>
#include "util.h"
#include "store.h"

#define  FILE_TYPE_PKTS                   1
#define  FILE_TYPE_JSON                   2

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;

int writeBlankFile(int type);
int storeFile(FILE *fp, char *buf, int size);
void deleteEarlyFile(int type);

int initStore(const char *path, int space, int type)  // init store handle
{
  int v, len;
  char buf[1024];
  StoreInfoT *psi;

  strcpy(buf, path);
  len = strlen(buf);
  if(buf[len-1] == 47){
    buf[len-1] = 0;
    len--;
  }
  if(type == FILE_TYPE_PKTS){
    psi = &(globalValue.siPkts);
    strcpy(psi->prefix, "pcap");
    v = DEFAULT_PKTS_SPACE;
    if(readOnlyGlobal.configInfo.pcapFileSize > 0)
      v = readOnlyGlobal.configInfo.pcapFileSize;
  }
  if(type == FILE_TYPE_JSON){
    psi = &(globalValue.siJson);
    strcpy(psi->prefix, "json");
    v = DEFAULT_JSON_SPACE;
  }
  if(psi == 0)
    return -1;
  strcpy(psi->localDir, buf);
  psi->fileSize = v * 1024 * 1024;
  psi->fileCount = space / v;
  if(psi->fileCount >= 1000)
    psi->fileCount = 999;
  psi->currSize = 0;
  psi->currInd = 0;

  memset(buf, 0x00, 1024);
  getcwd(buf, 1024);
  if(chdir(path))
    return STORE_ERROR_WRONG_DIRECTIONARY;
  chdir(buf);
  v = writeBlankFile(type); // Write an empty file and take up space
  if(v < 0)
    return v;
  return 0;
}

int initStorePkts(const char *path, int space)  // init packet store handle
{
  int v;

  v = initStore(path, space, FILE_TYPE_PKTS);
  if(v)
    return v;
  readOnlyGlobal.enablePkts = 1;
  return 0;
}

int initStoreJson(const char *path, int space)  // init json store handle
{
  int v;

  v = initStore(path, space, FILE_TYPE_JSON);
  if(v)
    return v;
  readOnlyGlobal.enableJson = 1;
  return 0;
}

int newFile(int type, time_t tt)  // Open new file
{
  int num;
  FILE *fp;
  StoreInfoT *psi;
  char buf[256], tmp[256];
  unsigned char ubuf[256];

  psi = 0;
  if(type == FILE_TYPE_PKTS)
    psi = &(globalValue.siPkts);
  if(type == FILE_TYPE_JSON)
    psi = &(globalValue.siJson);
  if(psi == 0)
    return -1;
  if(psi->currInd >= psi->fileCount)
    psi->currInd = 0;
  psi->currInd++;
  deleteEarlyFile(type);
  getFileStrTime(tt, tmp);
  sprintf(buf, "%s/%s-%s-%s.%s", psi->localDir, DEFAULT_FILE_PREFIX, readOnlyGlobal.configInfo.devName, tmp, psi->prefix);
  fp = fopen(buf, "w");
  if(fp == 0)
    return -1;
  psi->fp = fp;
  psi->currSize = 0;
  if(type == FILE_TYPE_JSON)
    return 0;
  num = makeHeaderBuf(ubuf);
  storeFile(fp, (char*)ubuf, num);
  psi->currSize = num;
  return 0;
}

void dumpPkt(const struct pcap_pkthdr *h, const u_char *pkt)  // Write packet data into file
{
  int v, num;
  u_char udata[65536];
  StoreInfoT *psi;
  ptcs_pkthdr hdr;

  psi = &(globalValue.siPkts);
  if(psi->currSize == 0){  // Check new file
    if(newFile(FILE_TYPE_PKTS, h->ts.tv_sec))
      return;
  }
  hdr.tv_sec = h->ts.tv_sec;
  hdr.tv_usec = h->ts.tv_usec;
  hdr.caplen = h->caplen;
  hdr.len = h->len;
  if(hdr.caplen > 65500)
    hdr.caplen = 65500;
  v = readOnlyGlobal.configInfo.maxLength;
  if((hdr.caplen > v) && (v > 0))
    hdr.caplen = v;
  if(hdr.len > hdr.caplen)
    hdr.len = hdr.caplen;
  memcpy(udata, &hdr, sizeof(ptcs_pkthdr));
  v = sizeof(ptcs_pkthdr);
  memcpy(udata + v, pkt, hdr.caplen);
  v += hdr.caplen;
  num = v;
  v = storeFile(psi->fp, (char*)udata, num);
  if(v <= 0)
    return;
  psi->currSize += num;
  if(psi->currSize > psi->fileSize){ // The file is full
    fclose(psi->fp);
    psi->fp = 0;
    psi->currSize = 0;
  }
  return;
}

void dumpPktEnd()
{
  StoreInfoT *psi;

  psi = &(globalValue.siPkts);
  if(psi->fp)
    fflush(psi->fp);
}

void writeJson(const char *str, time_t tt)  // Write json data into file
{
  int len, v;
  char buf[4096];
  StoreInfoT *psi;

  psi = &(globalValue.siJson);
  if(psi->currSize == 0){  // Check new file
    if(newFile(FILE_TYPE_JSON, tt))
      return;
  }
  sprintf(buf, "%s\r\n\r\n", str);
  len = strlen(buf);
  v = storeFile(psi->fp, buf, len);
  if(v <= 0)
    return;
  psi->currSize += len;
  if(psi->currSize > psi->fileSize){ // The file is full
    fclose(psi->fp);
    psi->fp = 0;
    psi->currSize = 0;
  }
  return;
}

void writeJsonEnd()
{
  StoreInfoT *psi;

  psi = &(globalValue.siJson);
  if(psi->fp)
    fflush(psi->fp);
}

int writeBlankFile(int type)
{
  int i, j, n, v;
  FILE *fp;
  char buf[1024];
  StoreInfoT *psi;

  psi = 0;
  v = 0;
  if(type == FILE_TYPE_PKTS){
    psi = &(globalValue.siPkts);
    v = readOnlyGlobal.configInfo.pcapFileSize;
  }
  if(type == FILE_TYPE_JSON){
    psi = &(globalValue.siJson);
    v = 10;
  }
  if(psi == 0)
    return -1;
  sprintf(buf, "rm -f %s/%s*.%s", psi->localDir, DEFAULT_FILE_PREFIX, psi->prefix);
  system(buf);
  for(i = 1; i <= psi->fileCount; i++){
    sprintf(buf, "%s/%s-%s-%03dblank.%s", psi->localDir, DEFAULT_FILE_PREFIX, readOnlyGlobal.configInfo.devName, i, psi->prefix);
    fp = fopen(buf, "w");
    if(fp == 0)
      return STORE_ERROR_SYSTEM_FAILED;
    memset(buf, 0x00, 1024);
    for(j = 0; j < v*1024; j++){
      n = storeFile(fp, buf, 1024);
      if(n <= 0){
        fclose(fp);
        return STORE_ERROR_NO_SPACE;
      }
    }
    fclose(fp);
  }
  return 0;
}

int storeFile(FILE *fp, char *buf, int size)
{
  int i, num, v;
  
  i = 0;
  v = size;
  while(1){
    num = fwrite(buf + i, 1, v, fp);
    if(num <= 0)
      return 0;
    if(num >= v)
      break;
    v -= num;
    i += num;
  }
  return size;
}

int chekckEarlyFile(const char *fname, char *str) // Priority to delete blank files
{
  int i, len, type;
  const char *p;
  char buf[256];

  len = strlen(fname);
  p = 0;
  for(i = 0; i < len; i++){
    if(fname[i] == '-')
      p = fname + i + 1;
  }
  if(p == 0)
    return -1;
  strcpy(buf, p);
  len = strlen(buf);
  type = 2;
  p = strstr(fname, "blank");
  if(p)
    type = 1;
  for(i = 0; i < len; i++){
    if(buf[i] > '9')
      break;
    if(buf[i] < '0')
      break;
    str[i] = buf[i];
    str[i+1] = 0;
  }
  return type;
}

void deleteEarlyFile(int type)  // Delete the earliest file to achieve circular writing
{
  DIR *dir;
  StoreInfoT *psi;
  int blankFlag, v, v1, v2;
  char *p, buf[256], tmp[256];
  char strEarly[256], removeFile[256];
  struct dirent *entry;

  if(type == FILE_TYPE_PKTS)
    psi = &(globalValue.siPkts);
  if(type == FILE_TYPE_JSON)
    psi = &(globalValue.siJson);
  dir = opendir(psi->localDir);
  blankFlag = 0;
  strEarly[0] = 0;
  v1 = 0;
  v2 = 0;
  if(dir == NULL)
    return;
  while((entry = readdir(dir)) != NULL){
    if(entry->d_name[0] == '.')
      continue;
    sprintf(buf, "%s/%s", psi->localDir, entry->d_name);
    p = strstr(buf, psi->prefix);
    if(p == 0)
      continue;
    if(blankFlag){
      p = strstr(buf, "blank");
      if(p == 0)
        continue;
    }
    v = chekckEarlyFile(buf, tmp);
    if(v < 0)
      continue;
    if(v == 1)
      blankFlag = 1;
    if(blankFlag){
      if(v1 == 0){
        v1 = 1;
        sprintf(removeFile, "rm -f %s", buf);
        strcpy(strEarly, tmp);
        continue;
      }
      if(strcmp(strEarly, tmp) > 0){
        sprintf(removeFile, "rm -f %s", buf);
        strcpy(strEarly, tmp);
        continue;
      }
      continue;
    }
    if(v2 == 0){
      v2 = 1;
      sprintf(removeFile, "rm -f %s", buf);
      strcpy(strEarly, tmp);
      continue;
    }
    if(strcmp(strEarly, tmp) > 0){ // File time comparison
      sprintf(removeFile, "rm -f %s", buf);
      strcpy(strEarly, tmp);
    }
  }
  system(removeFile);
}
