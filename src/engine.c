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

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "engine.h"
#include "log.h"
#include "data.h"
#include "util.h"
#include "store.h"
#include "process.h"
#include "check.h"

extern ReadOnlyGlobalT readOnlyGlobal;
extern GlobalValueT globalValue;
pcap_t *caphandler;

#define LO_MAC_FILE "/etc/Tmarlin-lomac"
#define OFFSETMASK 0x1FFF

int checkSection(struct pcap_pkthdr *phdr, const u_char *sp, int *ind);  // Check fragment packets

void displayNetCard()  // Show all network cards
{
  int i, cnt = 0;
  u_int32_t addr;
  struct sockaddr_in sin;
  struct pcap_addr *paddr;
  pcap_if_t *dev, *allDevs;
  char name[128], errbuf[2048];
  DevInfoT devInfos[MAX_DEVICE];

  if(pcap_findalldevs(&allDevs, errbuf) > 0){
    printf("get net card info failed\n");
    return;
  }
  dev = allDevs;
  while(dev != 0){
    strcpy(name, dev->name);
    paddr = dev->addresses;
    dev = dev->next;
    if (NULL == dev) break;
    if (cnt >= MAX_DEVICE) break;
    if (0 == dev->name[0]) continue;
    while(paddr){
      memcpy(&sin, paddr->addr, sizeof(struct sockaddr));
      paddr = paddr->next;
      if(sin.sin_family != AF_INET)
        continue;
      addr = htonl(sin.sin_addr.s_addr);
      if(addr == 0)
        continue;
      strcpy(devInfos[cnt].dev, name);
      devInfos[cnt].addr = addr;
      cnt++;
    }
  }
  for(i = 0; i < cnt; i++){
    addr = devInfos[i].addr;
    printf("card %s, ip %d.%d.%d.%d\n", devInfos[i].dev, addr/256/256/256, addr/256/256%256, addr/256%256, addr%256);
  }
  return;
}

int initPacketHandler()
{
  FILE *fp;
  int i, rc, fd;
  struct ifreq ifr;
  char errbuf[1024];
  struct sockaddr_in *addr = NULL;

  caphandler = pcap_open_live(readOnlyGlobal.configInfo.devName, 65536, 0, 0, errbuf);
  if(caphandler == 0){
    writeLog(PROBE_LOG_WARNING, "User rights are insufficient. You cannot run this program on this device. Please increase your system permissions");
    return -1;
  }

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);  // Get IP address of capture network card
  if (fd == -1) return -1;
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, readOnlyGlobal.configInfo.devName, IFNAMSIZ - 1);
  if ((rc = ioctl(fd, SIOCGIFADDR, &ifr)) != 0) {
    writeLog(PROBE_LOG_WARNING, "get %s ip address failed", readOnlyGlobal.configInfo.devName);
    close(fd);
  } else {
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    readOnlyGlobal.devAddress = *addr;
    close(fd);
  }
  fd = socket(AF_INET,SOCK_STREAM,0);
  if ((rc = ioctl(fd, SIOCGIFHWADDR, &ifr)) != 0) {
    writeLog(PROBE_LOG_WARNING, "get %s mac address failed", readOnlyGlobal.configInfo.devName);
    close(fd);
  } else {
    for(i = 0; i < 6; i++){
      sprintf(readOnlyGlobal.devMac+2*i, "%02X", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    }
    memcpy(readOnlyGlobal.mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
  }
  if (0 == strcmp(readOnlyGlobal.devMac, "000000000000")) {
    if (-1 == (access(LO_MAC_FILE, F_OK))) {
      fp = fopen(LO_MAC_FILE, "w");
      if (NULL == fp) {
        writeLog(PROBE_LOG_WARNING, "Can not create %s", LO_MAC_FILE);
        return -1;
      } else {
        fprintf(fp, "lo%d", (int)time(NULL));
        fclose(fp);
      }
    }
    fp = fopen(LO_MAC_FILE, "r");
    fgets(readOnlyGlobal.devMac, 64, fp);
    fclose(fp);
  }
  return 0;
}

void *processThread(void *arg)
{
  int nRet, discard, ind, v;
  const u_char *pkt, *pkt1;
  struct pcap_pkthdr *phdr, hdr;
  PacketInfoT *pPacketInfo;

  while(readOnlyGlobal.runFlag){
    if(readOnlyGlobal.pause){
      sleep(1);
      continue;
    }
    nRet = pcap_next_ex(caphandler, &phdr, &pkt);
    if(!readOnlyGlobal.licenseRun){
      sleep(1);
      continue;
    }
    if(nRet == 0)
      continue;
    if(nRet <= 0)
      break;
    if(pkt == 0)
      break;
    if(phdr->caplen <= 0)
      break;
    globalValue.currTime = phdr->ts.tv_sec;
    globalValue.realCurrTime = phdr->ts.tv_sec;
    discard = 0;
    ind = 0;
    v = checkSection(phdr, pkt, &ind);
    if(v == 0){
      phdr->caplen -= ind;
      phdr->len -= ind;
      pkt += ind;
      processPacket(phdr, pkt, &discard); // Normal packet
    }
    if(v < 0)  // Fragmentation packet
      continue;
    if(v > 0){  // Reassembling packets
      pPacketInfo = globalValue.pInfo + ind;
      v = pPacketInfo->shift;
      hdr.ts.tv_sec = phdr->ts.tv_sec;
      hdr.ts.tv_usec = phdr->ts.tv_usec;
      hdr.caplen = pPacketInfo->len - v;
      hdr.len = hdr.caplen;
      pkt1 = pPacketInfo->ubuf + v;
      pPacketInfo->valid = 0;
      processPacket(&hdr, pkt1, &discard);
    }
    if(discard)
      continue;
    pthread_mutex_lock(&(globalValue.processState.mutex));
    globalValue.processState.byte += phdr->len;
    globalValue.processState.pkt++;
    pthread_mutex_unlock(&(globalValue.processState.mutex));
    if(readOnlyGlobal.enablePkts){
      if(v > 0)
        dumpPkt(&hdr, pkt1);  // Save packet to file
      else
        dumpPkt(phdr, pkt);
      if(globalValue.flushPkts){
        dumpPktEnd();
        globalValue.flushPkts = 0;
      }
    }
    if(readOnlyGlobal.isPktExp){
      if(v > 0)
        exportPacketData(&hdr, pkt1);  // Send packets to the specified location
      else
        exportPacketData(phdr, pkt);
    }
  }
  if (NULL != caphandler) {
    pcap_close(caphandler);
  }
  return 0;
}

int checkSection(struct pcap_pkthdr *phdr, const u_char *sp, int *ind)
{
  const struct ip *sip;
  const struct udphdr *udp;
  u_int32_t src, dst, vid, packetID;
  u_short off;
  int shift, i, v;
  int ipLen, proto, offset;
  PacketInfoT *pPacketInfo;
  const u_char *payload;

  shift = 0;
  vid = 0;
  if((sp[12] == 0x81) && (sp[13] == 0x00)){
    vid = sp[14] % 16 * 256 + sp[15];
    shift = 4;
    if((sp[16] == 0x81) && (sp[17] == 0x00))
      shift = 8;
  }
  if((sp[12] == 0x88) && (sp[13] == 0x47)){
    shift = 4;
    if((sp[16] & 0x01) == 0)
      shift = 8;
  }
  sip = (const struct ip*)(sp + shift + 14);
  proto = sip->ip_p;
  packetID = ntohs(sip->ip_id);
  src = ntohl(sip->ip_src.s_addr);
  dst = ntohl(sip->ip_dst.s_addr);
  ipLen = sp[14 + shift] % 16;
  ipLen *= 4;
  offset = ntohs(sip->ip_off) & OFFSETMASK;
  off = ntohs(sip->ip_off);
  for(i = 0; i < MAX_PACKET_COUNT; i++){  // According to the packet ID number, find the previous fragment packet
    pPacketInfo = globalValue.pInfo + i;
    if(pPacketInfo->valid == 0)
      continue;
    if((src == pPacketInfo->src) && (dst == pPacketInfo->dst) && (pPacketInfo->packetID == packetID) && (vid == pPacketInfo->vid)){
      payload = sp + shift + 14 + ipLen;
      v = phdr->caplen - shift - 14 - ipLen;
      memcpy(pPacketInfo->ubuf + pPacketInfo->len, payload, v);
      pPacketInfo->len += v;
      *ind = i;
      if(off & 0x2000) // It's piecemeal
        return -1;
      return 1;  // This is the complete package
    }
  }
  if(proto == 47){
    v = 14 + shift + ipLen + offset + 8;
    if(readOnlyGlobal.isPktExp && (dst == readOnlyGlobal.expPktNumIP))
      return -1;  // Packets sent by yourself, not processed
    *ind = v;
  }
  if(proto == 17){
    udp = (struct udphdr*)(sp + 14 + shift + ipLen + offset);
    v = ntohs(udp->dest);
    if(v == 4789){
      if(readOnlyGlobal.isPktExp && (dst == readOnlyGlobal.expPktNumIP))
        return -1;  // Packets sent by yourself, not processed
    }
    v = 14 + shift + ipLen + offset + sizeof(struct udphdr) + 8;
    *ind = v;
  }
  if(!(off & 0x2000)) // Normal packet
    return 0;
  for(i = 0; i < MAX_PACKET_COUNT; i++){ // Record fragmented packets
    pPacketInfo = globalValue.pInfo + i;
    if(pPacketInfo->valid)
      continue;
    pPacketInfo = globalValue.pInfo + i;
    pPacketInfo->src = src;
    pPacketInfo->dst = dst;
    pPacketInfo->packetID = packetID;
    pPacketInfo->vid = vid;
    pPacketInfo->valid = 1;
    memcpy(pPacketInfo->ubuf, sp, phdr->caplen);
    pPacketInfo->len = phdr->caplen;
    pPacketInfo->shift = v;
    return -1;
  }
  pPacketInfo = globalValue.pInfo;
  pPacketInfo[1].valid = 0;
  pPacketInfo[2].valid = 0;
  pPacketInfo[3].valid = 0;
  pPacketInfo->src = src;
  pPacketInfo->dst = dst;
  pPacketInfo->packetID = packetID;
  pPacketInfo->vid = vid;
  pPacketInfo->valid = 1;
  memcpy(pPacketInfo->ubuf, sp, phdr->caplen);
  pPacketInfo->len = phdr->caplen;
  pPacketInfo->shift = v;
  return -1;
}
