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
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include "ui.h"
#include "log.h"
#include "data.h"
#include "util.h"
#include "scan.h"
#include "check.h"
#include "store.h"
#include "config.h"
#include "ipm_version.h"
#include "engine.h"
#include "commpair.h"
#ifdef PROCESS_FLOW
#include "inode.h"
#endif

ReadOnlyGlobalT readOnlyGlobal;
GlobalValueT globalValue;

extern int dispmain(int argc, char *argv[]);
extern int playmain(int argc, char *argv[]);

void printUsage()  // Print help infomation
{
  printf("%s Cloud Traffic Probe 3.0\n\n", readOnlyGlobal.progName);
  printf("\033[32m*** This help is also available at https://www.tcpiplabs.com/jft_help_english\033[0m\n");
  printf("\033[32m*** %s needs to run as root user, or use ??sudo?? to upgrade user rights\033[0m\n", readOnlyGlobal.progName);
  printf("\033[32m*** %s can automatically resolve VXLAN and GRE protocols\033[0m\n", readOnlyGlobal.progName);
  printf("\033[32m*** If you need to analyze more NICs, pls run more %ss\033[0m\n\n", readOnlyGlobal.progName);
  printf("\033[33m%s 3.0 contains 17 commands in 4 categories\033[0m\n", readOnlyGlobal.progName);
  printf("  1. Basic commands\n");
  printf("  2. Commands for TCP/UDP and URL/SQL session KPIs & KQIs, process name/CPU/memory\n");
  printf("  3. Commands for Raw Packets and PCAP\n");
  printf("  4. Tmarlin online traffic monitoring (Prepaid services)\n\n");

  printf("\033[33m1. Basic commands:\033[0m\n");
  printf("    -h                          Print this help\n");
  printf("    -k                          Print all KPIs that %s can analyze and output to JSON\n", readOnlyGlobal.progName);
  printf("    -e                          Print all examples\n");
  printf("    -r                          Run in daemon mode\n");
  printf("    -c                          Automatically detect and output HTTP session\n");
  printf("    -i <interface>              Capture interface\n");
  printf("    -s <analyze-object>         Fill in IP/Subnet/IP~IP/IP:Port for analysis object\n");
  printf("    -t <object-type>            Fill in TCP_UDP/TCP/UDP/HTTP/Oracle/SQLserver/MySQL,\n");
  printf("                                \033[33mIf -t is not entered, it means -t TCP_UDP\033[0m\n\n");
  printf("    Examples for basic:\n");
  printf("    1. %s -i eth0 -r\n\n", readOnlyGlobal.progName);

  printf("\033[33m2. Commands for TCP/UDP and URL/SQL session KPIs & KQIs, and process information:\033[0m\n");
  printf("    -j <json local path>        Local path used to store JSON files\n");
  printf("    -y <json space size>        Space size for -j, must be a multiple of 100MB, FIFO cover logic\n");
  printf("    -d <export json address>    KPI/URL/SQL of session in JSON will be sent to this IP:Port real time\n");
  printf("    -q <query conditions>       Query or playback session history data from JSON files,\n");
  printf("                                \033[33mNotice: the query representation in the example 4\033[0m\n");
  printf("    -u <query URL/SQL>          In the JSON files, query JSON entries containing URL/SQL key words\n");
  printf("    -o <file path>              Path to dump the results of query JSON as a csv file\n\n");
  printf("    Examples for storing, forwarding, querying JSON:\n");
  printf("    1. %s -i eth0 -j /tmp/ -y 1000 -c\n", readOnlyGlobal.progName);
  printf("    2. %s -i eth0 -s 10.10.10.89:1521 -t oracle -j /tmp/ -y 1000\n", readOnlyGlobal.progName);
  printf("    3. %s -i eth0 -s 10.10.10.87 -t tcp -s 10.10.10.88:80 -t http -d 192.168.1.12:9015\n", readOnlyGlobal.progName);
  printf("    4. %s -q \"2020-02-17 15:00:00\" \"2020-02-17 16:02:00\" 172.31.9.10,10.10.10.20 -o /root/\n\n", readOnlyGlobal.progName);

  printf("\033[33m3. Commands for Raw Packets and PCAP:\033[0m\n");
  printf("    -l <pcap local path>        Local path used to store PCAP files\n");
  printf("    -z <pcap space size>        Space size for -l, must be a multiple of 100MB, FIFO cover logic\n");
  printf("    -m <pcap file size>         File size for -m, the unit is trillion(M)\n");
  printf("    -b <max packet length>      Raw packets will be truncated to this length\n");
  printf("    -f <play conditions>        Playback history raw packets from PCAP files to IP:4789 with VXLAN\n");
  printf("                                \033[33mNotice: the query representation in the example 3\033[0m\n");
  printf("    -x <export pcap address>    Raw packets will be forwarded or playbacked to this address\n");
  printf("                                \033[33mNotice: this command will use VXLAN, port 4789 must be opened\033[0m\n");
  printf("                                \033[33mNotice: Use -x alone to forward raw packets in real time to this address\033[0m\n");
  printf("                                \033[33mNotice: Use with -f to playback raw packets from PCAP to this address\033[0m\n\n");
  printf("    Examples for Raw Packets and PCAP:\n");
  printf("    1. %s -i eth0 -s 192.168.1.10 -s 192.168.1.11 -l /tmp/ -z 1000 -m 1 -j /opt/ -y 1000\n", readOnlyGlobal.progName);
  printf("    2. %s -i eth0 -x 10.10.10.20 -b 512\n", readOnlyGlobal.progName);
  printf("    3. %s -f \"2020-02-17 15:00:00\" \"2020-02-17 16:02:00\" -x 192.168.1.12:4789\n\n", readOnlyGlobal.progName);

  printf("\033[33m4. Tmarlin online traffic monitoring (Prepaid services):\033[0m\n");
  printf("    -v <export json address>    Address of Tmarlin traffic monitoring service, default port 9015\n");
  printf("    -u <account>                User's Tmarlin login account\n");
  printf("    -p <password>               User's Tmarlin account password\n\n");
  printf("    Examples for use Tmarlin:\n");
  printf("    1. %s -u your_account -p your_password -i eth0 -v 192.168.1.12\n\n", readOnlyGlobal.progName);
  printf("\033[32m*** For more information, please visit www.tcpiplabs.com, TCPIPLABS TECH., INC. (c) 2015-2020.\033[0m\n");
}

void printExample()  // Print exapmle infomation
{
  printf("Examples:\n"
      "    Q1. Analyze the total traffic of the host NIC, and reserve 1GB space on the host,\n"
      "        store TCP & UDP session KPIs in the JSON file in FIFO logic\n"
      "    \033[33mA1. %s -i eth0 -j /tmp/ -y 1000\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q2. Analyze the Oracle traffic, reserve 1GB space on the Oracle host,\n"
      "        and store SQLs and KPIs in the JSON file in FIFO logic\n"
      "    \033[33mA2. %s -i eth0 -s 10.10.10.89:1521 -t oracle -j /tmp/ -y 1000\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q3. Analyze the traffic of the two VMs of a cloud node server, one VM with TCP analysis and another VM with HTTP/URL analysis,\n"
      "        and export the JSON data to an external data collector in real time\n"
      "    \033[33mA3. %s -i eth0 -s 10.10.10.87 -t tcp -s 10.10.10.88:80 -t http -d 192.168.1.12:9015\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q4. Analyze the traffic of the two IPs of a host NIC, and reserve 1GB space for raw packets/PCAP,\n"
      "        and another 1GB space for JSON in this host\n"
      "    \033[33mA4. %s -i eth0 -s 192.168.1.10 -s 192.168.1.11 -t udp -l /tmp/ -z 1000 -m 1 -j /opt/ -y 1000\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q5. Real-time forward all traffic of host NIC to external storage path\n"
      "    \033[33mA5. %s -i eth0 -x 10.10.10.20\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q6. Query the historical data of two IPs from JSON files, and output the query results to the CSV file of the specified path\n"
      "    \033[33mA6. %s -q \"2020-02-17 15:00:00\" \"2020-02-17 16:02:00\" 172.31.9.10,10.10.10.20 -u www.sina.com -o /root/\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q7. Playback historical data from JSON file, and output the query results to the CSV file of the specified path\n"
      "    \033[33mA7. %s -q \"2020-02-17 15:00:00\" \"2020-02-17 16:02:00\" -o /root/\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q8. Playback historical data from PCAP file, and output to destination address\n"
      "    \033[33mA8. %s -f \"2020-02-17 15:00:00\" \"2020-02-17 16:02:00\" -x 192.168.1.12:4789\033[0m\n"
      "    \n", readOnlyGlobal.progName);
  printf("    Q9. Connect to Tmarlin online traffic monitoring service\n"
      "    \033[33mA9. %s -u your_account -p your_password -i eth0 -v 192.168.1.12\033[0m\n"
      "    \n"
      "    \033[32m*** TCPIPLABS TECH., INC. (c) 2015-2020\033[0m\n", readOnlyGlobal.progName);
}

void printKpi()  // Print KPI infomation
{
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("| Num | KPI                   | Algorithm                                                      |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  1  | src/dstBytes          | Number of bytes received by src/dst endpoint                   |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  2  | src/dstRetransPkts    | Number of retransmitted packets received by src/dst            |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  3  | src/dstLossRatio      | Number of retransmitted packets received by the src/dst /      |\n");
  printf("|     |                       | Total number of TCP packets received by src/dst                |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  4  | responseTime          | Time difference between the first request packet and the       |\n");
  printf("|     |                       | first response packet                                          |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  5  | src/dstNetLatency     | Time difference between sending data to src/dst and            |\n");
  printf("|     |                       | receiving dst/src [ACK]                                        |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  6  | dstHandTime           | Time difference between sending [SYN] to dst and               |\n");
  printf("|     |                       | receiving dst [SYN,ACK]                                        |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  7  | srcHandTime           | Time difference between sending [SYN,ACK] to src and           |\n");
  printf("|     |                       | receiving src [ACK]                                            |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  8  | loadTransTime         | Time difference between the first response packet and the last |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  9  | src/dstRetransTime    | The time difference between the last retransmitted packet sent |\n");
  printf("|     |                       | to the src/dst and the sending packet                          |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  10 | src/dstPkts           | Number of packets received by src/dst endpoint                 |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  11 | src/dstSynPkts        | Number of [SYN] Packet received by src/dst                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  12 | src/dstSynAckPkts     | Number of [SYN,ACK] Packet received by src/dst                 |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  13 | src/dstRstPkts        | Number of [RST] Packet received by src/dst                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  14 | src/dstFinPkts        | Number of [FIN] Packet received by src/dst                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  15 | src/dstTinyPkts       | Number of Less than 64 packets received by src/dst             |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  16 | src/dstZeroWinPkts    | Number of Zero Window Packet send from src/dst                 |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  17 | largePkts             | Number of More than 1514 packets                               |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  18 | avgPktLen             | Total bytes / total packets                                    |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  19 | Program               | Associated process                                             |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  20 | CPU                   | CPU utilization of process                                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  21 | MEM                   | Memory usage of process                                        |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  22 | src/dstConDelayUsec   | Time difference between tcp handshake                          |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  23 | begintime             | Business start time                                            |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  24 | endtime               | Business end time                                              |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  25 | response              | Time difference between the last request packet and the        |\n");
  printf("|     |                       | first response packet                                          |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  26 | pageload              | Time difference between the last request packet and the        |\n");
  printf("|     |                       | last response packet                                           |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  27 | retcode               | HTTP(database) return code                                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  28 | method                | HTTP method(like GET/POST)                                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  29 | url                   | Uniform Resource Locator                                       |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  30 | domain                | Name of the domain                                             |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  31 | contentType           | Type of content                                                |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  32 | forward               | Original address                                               |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  33 | agent                 | Browser version                                                |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  34 | sql                   | Structured Query Language                                      |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  35 | err                   | Database error description                                     |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  36 | dbname                | Database name                                                  |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
  printf("|  37 | user                  | User name of database                                          |\n");
  printf("+----------------------------------------------------------------------------------------------+\n");
}

void daemonize()
{
  int i;
  pid_t pid;

  signal(SIGHUP ,SIG_IGN);
  pid = fork();
  if (pid < 0) {
    printf("fork error!\n");
    exit(-1);
  }
  if (pid > 0)
    exit(-1);
  pid = setsid();
  umask(0);
  if (pid == -1) {
    printf("setsid error!\n");
    exit(-1);
  }
  pid = fork();
  if (pid)
    exit(-1);
  chdir("/tmp");
  for(i = 0; i < 256; i++)
    close (i);
  open("/dev/null", O_RDONLY);
  open("/dev/null", O_WRONLY);
  open("/dev/null", O_WRONLY);
  return;
}

void terminateProcess(int signo)
{
  StoreInfoT *psi;

  readOnlyGlobal.runFlag = 0;
  psi = &(globalValue.siPkts);
  if(psi->fp)
    fclose(psi->fp);
  psi = &(globalValue.siJson);
  if(psi->fp)
    fclose(psi->fp);
}

void getSelfProcessName(char *str)
{
  int i, len;
  char buf[256], *p;

  strcpy(buf, str);
  len = strlen(buf);
  for(i = 0; i < len; i++){
    if(buf[i] == '.')
      buf[i] = ' ';
    if(buf[i] == '/'){
      buf[i] = ' ';
      p = buf + i + 1;
    }
  }
  if(p){
    trim(p);
    p[31] = 0;
    strcpy(readOnlyGlobal.progName, p);
    return;
  }
  trim(buf);
  buf[31] = 0;
  strcpy(readOnlyGlobal.progName, buf);
}

int main(int argc, char *argv[])
{
  char *opttmp, buf[64], optbuf[64], *p;
  char localSpacePkts[32], localSpaceJson[32];
  int i, v, v1, v2, opt, online, dFlag;
  int checkFlag, haveDev;
  time_t tlast, tcurr;
  pthread_t processTid;
#ifdef PROCESS_FLOW
  time_t tt;
#endif

  v = 0;
  online = 0;
  haveDev = 0;
  checkFlag = 0;
  dFlag = 0;
  for(i = 1; i < argc; i++){
    if(!strcmp(argv[i], "-q")){
      dispmain(argc, argv);
      return 0;
    }
    if(!strcmp(argv[i], "-f")){
      playmain(argc, argv);
      return 0;
    }
  }
  if(argc == 1)
    v = 1;
  if((argc > 1) && !strcmp(argv[1], "-h"))
    v = 1;
  if((argc > 1) && !strcmp(argv[1], "-H"))
    v = 1;
  if(v == 1){
    sprintf(optbuf, "%s -a | more -d", argv[0]);
    system(optbuf);
    return 0;
  }
  if((argc == 2) && !strcmp(argv[1], "-i")){
    displayNetCard();
    return 0;
  }
  if((argc == 2) && !strcmp(argv[1], "-I")){
    displayNetCard();
    return 0;
  }

  memset(&readOnlyGlobal, 0x00, sizeof(ReadOnlyGlobalT));
  strcpy(readOnlyGlobal.sysVersion, SVN_VERSION);
  getSelfProcessName(argv[0]);
  if(argc == 1)
    readOnlyGlobal.loadFlag = 1;
  v1 = 0;
  v2 = 0;
  while ((opt = getopt(argc, argv, "aAeEkKi:I:u:U:p:P:s:S:t:T:j:J:y:Y:d:D:l:L:z:Z:b:B:x:X:v:V:M:m:CcRr")) != EOF) {
    switch(opt){
      case 'a':
      case 'A':
        printUsage();
        return -1;
      case 'j':
      case 'J':
        strcpy(readOnlyGlobal.configInfo.jsonPath, optarg);
        break;
      case 'm':
      case 'M':
        readOnlyGlobal.configInfo.pcapFileSize = atoi(optarg);
        break;
      case 'l':
      case 'L':
        strcpy(readOnlyGlobal.configInfo.pcapPath, optarg);
        break;
      case 'y':
      case 'Y':
        strcpy(localSpaceJson, optarg);
        readOnlyGlobal.configInfo.jsonSize = atoi(localSpaceJson);
        if(readOnlyGlobal.configInfo.jsonSize <= 100){
          printf("Json store space must large than 100M\n");
          return -1;
        }
        break;
      case 'z':
      case 'Z':
        strcpy(localSpacePkts, optarg);
        readOnlyGlobal.configInfo.pcapSize = atoi(localSpacePkts);
        if(readOnlyGlobal.configInfo.pcapSize <= 100){
          printf("Packet store space must large than 100M\n");
          return -1;
        }
        break;
      case 'b':
      case 'B':
        readOnlyGlobal.configInfo.maxLength = atoi(optarg);
        if(readOnlyGlobal.configInfo.maxLength < 64){
          printf("Packet length must more than 64\n");
          return -1;
        }
        break;
      case 'e':
        sprintf(optbuf, "%s -E | more -d", argv[0]);
        system(optbuf);
        return 0;
      case 'E':
        printExample();
        return -1;
      case 'k':
        sprintf(optbuf, "%s -K | more -d", argv[0]);
        system(optbuf);
        return 0;
      case 'K':
        printKpi();
        return -1;
      case 'i':
      case 'I':
        haveDev = 1;
        strcpy(readOnlyGlobal.configInfo.devName, optarg);
        break;
      case 's':
      case 'S':
        if (checkHostStr(optarg)) return -1;
        if(getHostInfo(optarg, &readOnlyGlobal.hostInfo[readOnlyGlobal.cntHost]) > 0){
          readOnlyGlobal.cntHost++;
          v1 = readOnlyGlobal.cntHost;
        }
        break;
      case 't':
      case 'T':
        setHostType(optarg, v1-1);
        v2++;
        break;
      case 'd':
      case 'D':
        if(readOnlyGlobal.isExp){
          writeLog(PROBE_LOG_WARNING, "-v and -d can not be specified at the same time");
          return -1;
        }
        strcpy(optbuf, optarg);
        if (NULL != (opttmp = strstr(optbuf, ":"))) {
          *opttmp = 0;
          strcpy(readOnlyGlobal.configInfo.expDomain, optbuf);
          readOnlyGlobal.configInfo.expPort = atoi(opttmp+1);
          readOnlyGlobal.isExp = 1;
          if (getDomainAddr(readOnlyGlobal.configInfo.expDomain, &readOnlyGlobal.expAddress, 
              &readOnlyGlobal.expNumIP, readOnlyGlobal.configInfo.expPort)) {
            writeLog(PROBE_LOG_WARNING, "Wrong address %s", readOnlyGlobal.configInfo.expDomain);
            return -1;
          }
        } else {
          writeLog(PROBE_LOG_WARNING, "Export address format must IP:PORT");
          return -1;
        }
        break;
      case 'x':
      case 'X':
        readOnlyGlobal.isPktExp = 1;
        readOnlyGlobal.expPktPort = 4789;
        strcpy(readOnlyGlobal.configInfo.expPktDomain, optarg);
        p = strstr(readOnlyGlobal.configInfo.expPktDomain, ":");
        if(p)
          *p = 0;
        if (getDomainAddr(readOnlyGlobal.configInfo.expPktDomain, &readOnlyGlobal.expPktAddress, 
              &readOnlyGlobal.expPktNumIP, 4789)) {
          return -1;
        }
        break;
      case 'v':
      case 'V':
        if(readOnlyGlobal.isExp){
          writeLog(PROBE_LOG_WARNING, "-v and -d can not be specified at the same time");
          return -1;
        }
        readOnlyGlobal.configInfo.expPort = 9015;
        strcpy(readOnlyGlobal.configInfo.expDomain, optarg);
        readOnlyGlobal.isExp = 1;
        if (getDomainAddr(readOnlyGlobal.configInfo.expDomain, &readOnlyGlobal.expAddress, 
            &readOnlyGlobal.expNumIP, 9015)) {
          writeLog(PROBE_LOG_WARNING, "Wrong address %s", readOnlyGlobal.configInfo.expDomain);
          return -1;
        }
        checkFlag = 1;
        break;
      case 'u':
      case 'U':
        strcpy(readOnlyGlobal.configInfo.username, optarg);
        break;
      case 'p':
      case 'P':
        strcpy(readOnlyGlobal.configInfo.password, optarg);
        break;
      case 'c':
      case 'C':
        readOnlyGlobal.configInfo.autoCheck = 1;
        break;
      case 'r':
      case 'R':
        dFlag = 1;
        break;
      default:
        return 0;
    }
  }

  v1 = 0;
  v2 = 0;
  if(readOnlyGlobal.configInfo.jsonPath[0] != 0)
    v1 = 1;
  if(readOnlyGlobal.configInfo.jsonSize > 0)
    v2 = 1;
  if((v1 == 0) && (v2 == 1)){  // Check json path
    printf("\"json local path(-j)\" and \"json space size(-y)\" must be all specified.\n");
    return 0;
  }
  if((v1 == 1) && (v2 == 0)){
    printf("\"json local path(-j)\" and \"json space size(-y)\" must be all specified.\n");
    return 0;
  }

  v1 = 0;
  v2 = 0;
  if(readOnlyGlobal.configInfo.pcapPath[0] != 0)
    v1 = 1;
  if(readOnlyGlobal.configInfo.pcapSize > 0)
    v2 = 1;
  if((v1 == 0) && (v2 == 1)){  // Check packet path
    printf("\"pcap local path(-l)\" and \"pcap space size(-z)\" must be all specified.\n");
    return 0;
  }
  if((v1 == 1) && (v2 == 0)){
    printf("\"pcap local path(-l)\" and \"pcap space size(-z)\" must be all specified.\n");
    return 0;
  }

  if((readOnlyGlobal.configInfo.pcapPath[0] != 0) && (readOnlyGlobal.configInfo.jsonPath[0] != 0)){  // Check that the paths are the same
    if(!strcmp(readOnlyGlobal.configInfo.pcapPath, readOnlyGlobal.configInfo.jsonPath)){
      printf("Json local path(-j) and pcap local path(-l) must not be the same\n");
      return 0;
    }
  }
  if (0 == haveDev && 1 == readOnlyGlobal.isExp) {
    writeLog(PROBE_LOG_ERROR, "Please Specific capture device");
    return 0;
  }

  if(dFlag)
    daemonize();
  loadAndSaveConfig();
  if(readOnlyGlobal.loadFlag){
    if(readOnlyGlobal.configInfo.devName[0] != 0)
      haveDev = 1;
    if((readOnlyGlobal.isExp == 1) && ((readOnlyGlobal.configInfo.expPort == 9015) || (readOnlyGlobal.configInfo.expPort == 0)))
      checkFlag = 1;
  }
  signal(SIGINT, terminateProcess);
  signal(SIGTERM, terminateProcess);

  readOnlyGlobal.disableRepeat = 1;
  readOnlyGlobal.sessionTimeOut = DEFAULT_SESSION_TIMEOUT;

  if (initGlobalValue()) return -1;
  if (initCommPair()) return -1;
  if((readOnlyGlobal.configInfo.jsonPath[0] != 0) && (readOnlyGlobal.configInfo.jsonSize > 0)){  // Init json store
    v = initStoreJson(readOnlyGlobal.configInfo.jsonPath, readOnlyGlobal.configInfo.jsonSize);
    if(v == STORE_ERROR_WRONG_DIRECTIONARY){
      printf("Wrong json directionary!\n");
      return -1;
    }
    if(v == STORE_ERROR_SYSTEM_FAILED){
      printf("System error!\n");
      return -1;
    }
    if(v == STORE_ERROR_NO_SPACE){
      printf("No space on json directionary!\n");
      return -1;
    }
  }
  if((readOnlyGlobal.configInfo.pcapPath[0] != 0) && (readOnlyGlobal.configInfo.pcapSize > 0)){  // Init packet store
    v = initStorePkts(readOnlyGlobal.configInfo.pcapPath, readOnlyGlobal.configInfo.pcapSize);
    if(v == STORE_ERROR_WRONG_DIRECTIONARY){
      printf("Wrong pkts directionary!\n");
      return -1;
    }
    if(v == STORE_ERROR_SYSTEM_FAILED){
      printf("System error!\n");
      return -1;
    }
    if(v == STORE_ERROR_NO_SPACE){
      printf("No space on pkts directionary!\n");
      return -1;
    }
  }

  if (initLogFun()) return -1;
  if (haveDev && initPacketHandler()) return -1;

  if (-1 == chkLocalLicense()) {
    return -1;
  }

  readOnlyGlobal.isChk = initCheck();
  online = readOnlyGlobal.isChk;
  writeLog(PROBE_LOG_MESSAGE, "Network is %savailable", 1 == online?"":"un");
  if (online) {
    chkVersion();  // Check program version
    chkLicense();  // Check whether the license is valid
  } else {
    if (readOnlyGlobal.licenseValid < time(NULL)) {
      readOnlyGlobal.licenseRun = 0;
    } else {
      readOnlyGlobal.licenseRun = 1;
    }
  }
  getStrTime(readOnlyGlobal.licenseValid, buf);
  writeLog(PROBE_LOG_MESSAGE, "License is %savailable, until %s", 1 == readOnlyGlobal.licenseRun?"":"un", buf);

  if (readOnlyGlobal.isPktExp && initPacketSock()) return -1;
  if (online && readOnlyGlobal.isExp && initExpSock()) return -1;
  if (initUI()) return -1; 
  if (online) {
    if (chkUser()) { // Check whether username and password is valid
      return -1;
    }
    if((!readOnlyGlobal.isDolphin) && checkFlag){
      writeLog(PROBE_LOG_WARNING, "No permission, please log in www.tcpiplabs.com to register");
      return -1;
    }
    if (readOnlyGlobal.isLogin && readOnlyGlobal.isChk && readOnlyGlobal.isExp) {
      chkNicDid(readOnlyGlobal.configInfo.expDomain); // Get device id
    }
  } else if (!online && readOnlyGlobal.isExp) {
    writeLog(PROBE_LOG_WARNING, "You are offline, Export or Tmarlin must use online");
    return -1;
  }

  sleep(1);
  readOnlyGlobal.runFlag = 1;
  if (haveDev)
    pthread_create(&processTid, 0, processThread, 0);  // Create capture and process packet thread

  time(&tcurr);
  tcurr = getGlobalTime(tcurr);
  tlast = tcurr + 3;
  sleep(1);
#ifdef PROCESS_FLOW
  initMapping();
#endif
  while (haveDev && readOnlyGlobal.runFlag) {
    time(&tcurr);
#ifdef PROCESS_FLOW
    if(tcurr != tt)
      read_mapping();
    tt = tcurr;
#endif
    if((tlast - tcurr) > 20)
      tlast = getGlobalTime(tcurr) + 13;
    if(tcurr <= tlast){
      usleep(100000);
      continue;
    }
    scanFun();  // Display communication information with grid
    tlast += 10;
    getSelfUsage();
#ifdef PROCESS_FLOW
    initMapping();
#endif
  }
  return 0;
}
