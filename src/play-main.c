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
#include "play.h"
#include "config.h"
#include "util.h"
#include "disp-util.h"

int initPlaySock(PlayGlobalT *pGlobal, char *domain);
void getPcapFileList(PlayGlobalT *pGlobal);
void readPcapData(PlayGlobalT *pGlobal);
int playPacketData(PlayGlobalT *pGlobal, const struct pcap_pkthdr *h, const u_char *sp);

int playmain(int argc, char *argv[])  // Send history packet
{
  int v;
  char buf[1024];
  ConfigInfoT configInfo;
  PlayGlobalT playGlobal;

  memset(&playGlobal, 0x00, sizeof(PlayGlobalT));
  if(argc < 6){
    printf("Usage : %s [start] [end] -x dest_addr\n", argv[0]);
    return 0;
  }
  strcpy(buf, argv[2]);
  v = getTime(buf, &(playGlobal.tstart));
  if(v){
    printf("Wrong time %s\n", buf);
    return 0;
  }
  strcpy(buf, argv[3]);
  v = getTime(buf, &(playGlobal.tend));
  if(v){
    printf("Wrong time %s\n", buf);
    return 0;
  }
  if(playGlobal.tstart >= playGlobal.tend){
    printf("End time must large than start time\n");
    return 0;
  }
  if(strcmp("-x", argv[4])){
    printf("Usage : %s [start] [end] -x dest_addr\n", argv[0]);
    return 0;
  }
  strcpy(buf, argv[5]);
  if(initPlaySock(&playGlobal, buf))
    return 0;
  loadConfig(&configInfo);
  strcpy(playGlobal.pcapPath, configInfo.pcapPath);
  if((playGlobal.pcapPath[0] == 0) || (chkDir(playGlobal.pcapPath))){
    printf("Wrong pcap file path\n");
    return 0;
  }
  v = strlen(playGlobal.pcapPath);
  if(playGlobal.pcapPath[v - 1] == '/')
    playGlobal.pcapPath[v - 1] = 0;
  getPcapFileList(&playGlobal);
  readPcapData(&playGlobal);
  return 0;
}

void insertFile(PlayGlobalT *pGlobal, const char *filename, time_t tt)  // Put the valid file into the container
{
  int i, ind;

  if(pGlobal->cntFile >= MAX_PCAPFILE_COUNT)
    return;
  ind = -1;
  for(i = 0; i < pGlobal->cntFile; i++){
    if(tt < pGlobal->ftime[i]){
      ind = i;
      break;
    }
  }
  if(ind < 0){
    ind = pGlobal->cntFile;
    strcpy(pGlobal->pcapFile[ind], filename);
    pGlobal->ftime[ind] = tt;
    pGlobal->cntFile++;
    return;
  }
  for(i = pGlobal->cntFile-1; i >= ind; i--){
    strcpy(pGlobal->pcapFile[i+1], pGlobal->pcapFile[i]);
    pGlobal->ftime[i+1] = pGlobal->ftime[i];
  }
  strcpy(pGlobal->pcapFile[ind], filename);
  pGlobal->ftime[ind] = tt;
  pGlobal->cntFile++;
  return;
}

void getPcapFileList(PlayGlobalT *pGlobal)  // Get valid file
{
  time_t tt;
  DIR *dir;
  char buf[1024];
  struct stat fileInfo;
  struct dirent *entry;

  dir = opendir(pGlobal->pcapPath);
  if(dir == NULL)
    return;
  while((entry = readdir(dir)) != NULL){
    if(entry->d_name[0] == '.')
      continue;
    sprintf(buf, "%s/%s", pGlobal->pcapPath, entry->d_name);
    if(stat(buf, &fileInfo))
      continue;
    tt = fileInfo.st_mtime;
    if(tt < pGlobal->tstart)
      continue;
    insertFile(pGlobal, entry->d_name, tt);
  }
  closedir(dir);
}

void readPcapData(PlayGlobalT *pGlobal)  // Read packet data from pcap file
{
  int i, nRet;
  time_t tt;
  pcap_t *caphandler;
  const u_char *pkt;
  char tmp[1024], errbuf[1024];
  struct pcap_pkthdr *phdr;

  for(i = 0; i < pGlobal->cntFile; i++){
    sprintf(tmp, "%s/%s", pGlobal->pcapPath, pGlobal->pcapFile[i]);
    caphandler = pcap_open_offline(tmp, errbuf);
    if(caphandler == 0)
      continue;
    while(1){
      nRet = pcap_next_ex(caphandler, &phdr, &pkt);
      if((nRet > 0) && (pkt != NULL) && (phdr->caplen > 0)){
        tt = phdr->ts.tv_sec;
        if((pGlobal->tstart != 0) && (tt < pGlobal->tstart))
          continue;
        if((pGlobal->tend != 0) && (tt > pGlobal->tend))
          break;
        playPacketData(pGlobal, phdr, pkt);
        continue;
      }
      break;
    }
    pcap_close(caphandler);
  }
}

int initPlaySock(PlayGlobalT *pGlobal, char *domain)  // Init play socket
{
  socklen_t slen;
  char buf[1024], *p;
  int port;

  port = 4789;
  strcpy(buf, domain);
  p = strstr(buf, ":");
  if(p){
    *p = 0;
    p++;
    port = atoi(p);
    if(port == 0){
      printf("Wrong dest address %s\n", domain);
      return -1;
    }
  }
  if(getDomainAddr(buf, &(pGlobal->expAddr), &(pGlobal->addr), port)){
    printf("Wrong dest address %s\n", domain);
    return -1;
  }
  slen = sizeof(struct sockaddr_in);
  pGlobal->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (pGlobal->fd < 0){
    printf("socket error\n");
    return -1;
  }

  if (connect(pGlobal->fd, (struct sockaddr*)&(pGlobal->expAddr), slen) < 0){
    printf("connect export server %s failed: %s\n", domain, strerror(errno));
    close(pGlobal->fd);
    return -1;
  }
  return 0;
}

int playPacketData(PlayGlobalT *pGlobal, const struct pcap_pkthdr *h, const u_char *sp)  // Send packet data to destination
{
  int len, v;
  u_char ubuf[65536];

  ubuf[0] = 0x08;
  ubuf[1] = 0x00;
  ubuf[2] = 0x00;
  ubuf[3] = 0x00;
  ubuf[4] = 0x00;
  ubuf[5] = 0x00;
  ubuf[6] = 0xc8;
  ubuf[7] = 0x00;
  len = 8;
  v = h->caplen;
  if(v > 65536)
    v = 65536;
  memcpy(ubuf + len, sp, v);
  len += v;
  sendto(pGlobal->fd, (char*)ubuf, len, 0, (struct sockaddr *)&(pGlobal->expAddr), sizeof(struct sockaddr));
  return 0;
}
