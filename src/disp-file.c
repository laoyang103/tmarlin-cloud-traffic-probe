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
#include "disp-analyze.h"
#include "disp-util.h"

extern DispReadOnlyGlobalT dispReadOnlyGlobal;
extern DispGlobalValueT dispGlobalValue;

void insertFileNode(const char *filename, time_t tt);

void getFileList()  // Remove files out of time period
{
  time_t tt;
  DIR *dir;
  char *p, buf[1024];
  struct stat fileInfo;
  struct dirent *entry;

  dir = opendir(dispReadOnlyGlobal.filePath);
  if(dir == NULL)
    return;
  while((entry = readdir(dir)) != NULL){
    strcpy(buf, entry->d_name);
    if(buf[0] == '.')
      continue;
    if(stat(buf, &fileInfo))
      continue;
    tt = fileInfo.st_mtime;
    if(tt < dispReadOnlyGlobal.tstart)
      continue;
    p = strstr(buf, dispReadOnlyGlobal.devName);
    if(p == 0)
      continue;
    insertFileNode(entry->d_name, tt);
  }
  closedir(dir);
}

void insertFileNode(const char *filename, time_t tt)  // Put the file into the linked list
{
  FileNodeT *pnode, *ptmp;
  
  pnode = (FileNodeT*)malloc(sizeof(FileNodeT));
  if(pnode == 0)
    return;
  memset(pnode, 0x00, sizeof(FileNodeT));
  strcpy(pnode->filename, filename);
  pnode->lasttime = tt;
  ptmp = dispGlobalValue.pHead;
  dispGlobalValue.cntFile++;
  if(ptmp == 0){
    dispGlobalValue.pHead = pnode;
    return;
  }
  while(ptmp != 0){
    if(tt < ptmp->lasttime){
      pnode->next = ptmp;
      pnode->prev = ptmp->prev;
      if(pnode->prev != 0)
        pnode->prev->next = pnode;
      ptmp->prev = pnode;
      break;
    }
    if(ptmp->next == 0){
      ptmp->next = pnode;
      pnode->prev = ptmp;
      break;
    }
    ptmp = ptmp->next;
  }
}

void readData() // Read json data from file
{
  FILE *fp;
  char buf[1024], *p;
  FileNodeT *pnode;

  pnode = dispGlobalValue.pHead;
  while(pnode != 0){
    strcpy(buf, pnode->filename);
    pnode = pnode->next;
    fp = fopen(buf, "r");
    if(fp == 0)
      continue;
    while(1){
      p = fgets(buf, 1024, fp);
      if(p == 0)
        break;
      if(buf[0] == 0)
        break;
      if(buf[0] != '{')
        continue;
      analyzeJson(buf);
    }
    fclose(fp);
  }
}

int openExpFile()
{
  int v;

  v = chdir(dispReadOnlyGlobal.expPath);
  if(v)
    return -1;
  sprintf(dispGlobalValue.filename, "tmarlin-exp-%ld-%ld.csv", dispReadOnlyGlobal.tstart, dispReadOnlyGlobal.tend);
  dispGlobalValue.expFP = fopen(dispGlobalValue.filename, "w");
  if(dispGlobalValue.expFP == 0)
    return -1;
  return 0;
}

void expData()  // Put the session data into a CSV file
{
  int i, cnt;
  char buf[1024];
  char tmp1[64], tmp2[64];
  CommValueT *pCommValue;

  cnt = dispGlobalValue.cntValue;
  sprintf(buf, "start-time, end-time, source, destination, protocol, traffic, pkt, loss, avgPktLen, synPkts, tinyPkts, finPkts, rstPkts, largePkts, zeroWinPkts, rttDelay, synDelay, respDelay, loadDelay");
  fprintf(dispGlobalValue.expFP, "%s\n", buf);
  for(i = 0; i < cnt; i++){
    pCommValue = dispGlobalValue.pCommValue + i;
    getDispStrTime(pCommValue->time, tmp1);
    getDispStrTime(pCommValue->time+pCommValue->sec, tmp2);
    sprintf(buf, "%s, %s, ", tmp1, tmp2);

    getStrIP(pCommValue->src, tmp1);
    sprintf(tmp2, "%s:%d, ", tmp1, pCommValue->sport);
    strcat(buf, tmp2);

    getStrIP(pCommValue->dst, tmp1);
    sprintf(tmp2, "%s:%d, ", tmp1, pCommValue->dport);
    strcat(buf, tmp2);

    strcpy(tmp1, "TCP, ");
    if(pCommValue->proto == 17)
      strcpy(tmp1, "UDP, ");
    strcat(buf, tmp1);

    getDispTraffic(pCommValue->bytes, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->pkt, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->lose, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    sprintf(tmp2, "%d, ", pCommValue->avgLen);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->syn, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->tiny, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->fin, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->rst, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->largePkt, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    getDispPkts(pCommValue->zeroWin, tmp1);
    sprintf(tmp2, "%s, ", tmp1);
    strcat(buf, tmp2);

    sprintf(tmp1, "%.2f, ", pCommValue->rtt);
    strcat(buf, tmp1);

    sprintf(tmp1, "%.2f, ", pCommValue->synRtt);
    strcat(buf, tmp1);

    sprintf(tmp1, "%.2f, ", pCommValue->resp);
    strcat(buf, tmp1);

    sprintf(tmp1, "%.2f", pCommValue->load);
    strcat(buf, tmp1);
    fprintf(dispGlobalValue.expFP, "%s\n", buf);
  }
  fclose(dispGlobalValue.expFP);
  printf("export file : %s/%s\n", dispReadOnlyGlobal.expPath, dispGlobalValue.filename);
}
