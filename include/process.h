#ifndef _PROCESS_H_
#define _PROCESS_H_

void processPacket(const struct pcap_pkthdr *h, const u_char *sp, int *discard);

#endif
