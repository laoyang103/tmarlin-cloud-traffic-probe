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
#ifdef PROCESS_FLOW

#include "inode.h"

extern ReadOnlyGlobalT readOnlyGlobal;
INodeT selfNode, nodes[128];
int cntNode;

void getConnInode(char *file, int proto, int isNew);
void getSelfInfo();
void getPidInfo();
void getProgName(int pid, char *prog, char *strCPU, char *strMEM);

void initMapping()
{
  cntNode = 0;
}

void read_mapping()
{
  int isNew;

  isNew = 0;
  if(cntNode == 0){
    isNew = 1;
    memset(nodes, 0x00, sizeof(INodeT) * 128);
  }
  getConnInode("/proc/net/tcp", 6, isNew); // Get TCP connection information
  getConnInode("/proc/net/udp", 17, isNew); // Get UDP connection information
  getSelfInfo();
  getPidInfo();
}

void parseStrAddr(const char *src, u_int32_t *addr)
{
  unsigned int v, v1, v2, v3, v4;

  sscanf(src, "%X", &v);
  v1 = v % 256;
  v2 = v / 256 % 256;
  v3 = v / 256 / 256 % 256;
  v4 = v / 256 /256 / 256;
  *addr = v1*256*256*256 + v2*256*256  + v3*256 + v4;
}

void getConnInode(char *file, int proto, int isNew)
{
  FILE *fp;
  char buf[1024], *p;
  unsigned long inode;
  char rem_addr[128], local_addr[128];
  int local_port, rem_port, i, v;
  u_int32_t local, remote;
  INodeT *pnode;

  fp = fopen(file, "r");
  if(fp == 0)
    return;
  fgets(buf, 1024, fp);
  while(1){
    if(cntNode >= 128)
      break;
    p = fgets(buf, 1024, fp);
    if(p == 0)
      break;
    v = sscanf(buf, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
           local_addr, &local_port, rem_addr, &rem_port, &inode);
    if(v != 5)
      continue;
    if(inode == 0)
      continue;
    parseStrAddr(local_addr, &local);
    parseStrAddr(rem_addr, &remote);
    if((local == 0) || (remote == 0))
      continue;
    if(isNew){
      pnode = nodes + cntNode;
      pnode->local = local;
      pnode->remote = remote;
      pnode->localPort = local_port;
      pnode->remotePort = rem_port;
      pnode->proto = proto;
      pnode->inode = inode;
      cntNode++;
      continue;
    }
    v = 0;
    for(i = 0; i < cntNode; i++){
      pnode = nodes + i;
      if(inode == pnode->inode){
        v = 1;
        break;
      }
    }
    if(v == 0){
      pnode = nodes + cntNode;
      pnode->local = local;
      pnode->remote = remote;
      pnode->localPort = local_port;
      pnode->remotePort = rem_port;
      pnode->proto = proto;
      pnode->inode = inode;
      cntNode++;
    }
  }
  fclose(fp);
}

int isNumber(const char *str)
{
  int i, len;

  len = strlen(str);
  for(i = 0; i < len; i++){
    if(str[i] < '0')
      return 0;
    if(str[i] > '9')
      return 0;
  }
  return 1;
}

void getPidInfo2(int pid)  // Get a process information
{
  DIR * dir;
  int i, len;
  INodeT *pnode;
  unsigned long inode;
  struct dirent * entry;
  char buf[1024], buf2[1024], dirname[64], *p;

  sprintf(dirname, "/proc/%d/fd", pid);
  dir = opendir(dirname);
  if(!dir)
    return;
  while ((entry = readdir(dir))) {
    if (entry->d_type != DT_LNK)
      continue;
    sprintf(buf, "%s/%s", dirname, entry->d_name);
    len = readlink(buf, buf2, 79);
    if(len < 0)
      continue;
    buf2[len] = 0;
    if(strncmp(buf2, "socket:[", 8))
      continue;
    p = strstr(buf2, "]");
    if(p)
      *p = 0;
    inode = atoll(buf2+8);
    for(i = 0; i < cntNode; i++){
      pnode = nodes + i;
      if(inode == pnode->inode){
        if(pnode->pid != 0)
          break;
        pnode->pid = pid;
        getProgName(pid, pnode->name, pnode->strCPU, pnode->strMEM);
        break;
      }
    }
  }
  closedir(dir);
}

void getPidInfo()  //Get all process information
{
  DIR *dir;
  struct dirent * entry;

  dir = opendir("/proc");
  if(dir == 0)
    return;
  while ((entry = readdir(dir))) {
    if (entry->d_type != DT_DIR) continue;
    if (!isNumber (entry->d_name)) continue;
    getPidInfo2(atoi(entry->d_name));
  }
  closedir(dir);
}

void getSelfInfo() // Get own process information
{
  int i, len;
  FILE *fp;
  char *p, buf[1024];

  selfNode.pid = getpid();
  sprintf(buf, "ps -awxu 2>&1|grep %d|grep -v grep|awk '{print $3,$6}'", selfNode.pid);
  fp = popen(buf, "r");
  if(fp == 0)
    return;
  fgets(buf, 1024, fp);
  len = strlen(buf);
  if(buf[len - 1] == '\n'){
    buf[len - 1] = 0;
    len--;
  }
  p = 0;
  for(i = 0; i < len; i++){
    if(buf[i] == ' '){
      buf[i] = 0;
      p = buf + i + 1;
      break;
    }
    if(buf[i] == ','){
      buf[i] = 0;
      p = buf + i + 1;
      break;
    }
  }
  strcpy(selfNode.name, readOnlyGlobal.progName);
  strncpy(selfNode.strCPU, buf, 64);
  if(p)
    strncpy(selfNode.strMEM, p, 64);
  pclose(fp);
}

void getProgName(int pid, char *prog, char *strCPU, char *strMEM) // Get the process name, CPU and memory
{
  FILE *fp;
  int i, len;
  char buf[1024], *p;

  sprintf(buf, "ps -e 2>&1|grep %d|grep -v grep|awk '{print $4}'", pid);
  fp = popen(buf, "r");
  if(fp == 0)
    return;
  fgets(buf, 1024, fp);
  len = strlen(buf);
  if(buf[len - 1] == '\n')
    buf[len - 1] = 0;
  strncpy(prog, buf, 64);
  pclose(fp);

  sprintf(buf, "ps -awxu 2>&1|grep %d|grep -v grep|awk '{print $3,$6}'", pid);
  fp = popen(buf, "r");
  if(fp == 0)
    return;
  fgets(buf, 1024, fp);
  len = strlen(buf);
  if(buf[len - 1] == '\n'){
    buf[len - 1] = 0;
    len--;
  }
  p = 0;
  for(i = 0; i < len; i++){
    if(buf[i] == ' '){
      buf[i] = 0;
      p = buf + i + 1;
      break;
    }
    if(buf[i] == ','){
      buf[i] = 0;
      p = buf + i + 1;
      break;
    }
  }
  strncpy(strCPU, buf, 64);
  if(p)
    strncpy(strMEM, p, 64);
  pclose(fp);
}

int getProgInfo(CommMsgT *pCommMsg, int *pid, char *name, double *cpu, int *mem)  // Get process information according to communication information
{
  int i;
  INodeT *pnode;

  for(i = 0; i < cntNode; i++){
    pnode = nodes + i;
    if(pnode->proto != pCommMsg->proto)
      continue;
    if((pnode->local == pCommMsg->src) && (pnode->remote == pCommMsg->dst) && (pnode->localPort == pCommMsg->sport) && (pnode->remotePort == pCommMsg->dport)){
      *pid = pnode->pid;
      strncpy(name, pnode->name, 10);
      name[10] = 0;
      *cpu = atof(pnode->strCPU);
      *mem = atoi(pnode->strMEM);
      return 1;
    }
    if((pnode->local == pCommMsg->dst) && (pnode->remote == pCommMsg->src) && (pnode->localPort == pCommMsg->dport) && (pnode->remotePort == pCommMsg->sport)){
      *pid = pnode->pid;
      strncpy(name, pnode->name, 10);
      name[10] = 0;
      *cpu = atof(pnode->strCPU);
      *mem = atoi(pnode->strMEM);
      return 1;
    }
  }
  if((pCommMsg->dst == readOnlyGlobal.chkNumIP) && (pCommMsg->dport == readOnlyGlobal.chkPort)){
    *pid = selfNode.pid;
    strncpy(name, selfNode.name, 10);
    name[10] = 0;
    *cpu = atof(selfNode.strCPU);
    *mem = atoi(selfNode.strMEM);
    return 1;
  }
  return 0;
}

int getProgInfo2(NetSessionT *pSession, int *pid, char *name, double *cpu, int *mem)  // Get process information according to communication information
{
  int i;
  INodeT *pnode;

  for(i = 0; i < cntNode; i++){
    pnode = nodes + i;
    if(pnode->proto != pSession->proto)
      continue;
    if((pnode->local == pSession->src) && (pnode->remote == pSession->dst) && (pnode->localPort == pSession->sport) && (pnode->remotePort == pSession->dport)){
      *pid = pnode->pid;
      strcpy(name, pnode->name);
      *cpu = atof(pnode->strCPU);
      *mem = atoi(pnode->strMEM);
      return 1;
    }
    if((pnode->local == pSession->dst) && (pnode->remote == pSession->src) && (pnode->localPort == pSession->dport) && (pnode->remotePort == pSession->sport)){
      *pid = pnode->pid;
      strcpy(name, pnode->name);
      *cpu = atof(pnode->strCPU);
      *mem = atoi(pnode->strMEM);
      return 1;
    }
  }
  return 0;
}

#endif
