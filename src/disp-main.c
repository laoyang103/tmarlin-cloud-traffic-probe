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
#include "config.h"
#include "disp-util.h"
#include "disp-file.h"
#include "disp-process.h"

DispReadOnlyGlobalT dispReadOnlyGlobal;
DispGlobalValueT dispGlobalValue;

int dispmain(int argc, char *argv[])
{
  int i, j, v, vExp, len;
  time_t tt;
  ConfigInfoT configInfo;
  char buf[1024];

  v = 0;
  if((argc > 1) && !strcmp(argv[1], "-v"))
    v = 1;
  if(v == 0){
    strcpy(buf, argv[0]);
    strcat(buf, " -v");  // Add parameters to display historical data
    for(i = 1; i < argc; i++){
      strcat(buf, " ");
      len = strlen(argv[i]);
      v = 0;
      for(j = 0; j < len; j++){
        if(argv[i][j] == ' '){
          v = 1;
          break;
        }
      }
      if(v)
        strcat(buf, "\"");
      strcat(buf, argv[i]);
      if(v)
        strcat(buf, "\"");
    }
    strcat(buf, " | more -d");
    system(buf);  // Create child process for sub screen display
    return 0;
  }
  memset(&dispReadOnlyGlobal, 0x00, sizeof(DispReadOnlyGlobalT));

  strcpy(buf, argv[3]);  // get start time
  v = getTime(buf, &tt);
  if(v){
    printf("Wrong time %s\n", buf);
    return 0;
  }
  if((tt % 10) != 0)
    tt = tt - (tt % 10);
  dispReadOnlyGlobal.tstart = tt;

  strcpy(buf, argv[4]);  // get end time
  v = getTime(buf, &tt);
  if(v){
    printf("Wrong time %s\n", buf);
    return 0;
  }
  if((tt % 10) != 0)
    tt = tt - (tt % 10) + 10;
  dispReadOnlyGlobal.tend = tt;

  if(argc > 5){
    strcpy(buf, argv[5]);
    if(buf[0] != '-')
      getFilter(buf);
  }

  for(i = 0; i < argc; i++){
    if(!strcmp(argv[i], "-o") && ((i + 1) < argc)){  // Export csv file path of query result
      strcpy(dispReadOnlyGlobal.expPath, argv[i+1]);
      dispReadOnlyGlobal.isExp = 1;
    }
    if(!strcmp(argv[i], "-u") && ((i + 1) < argc)){  // Keywords for filtering strings
      strcpy(dispReadOnlyGlobal.content, argv[i+1]);
      dispReadOnlyGlobal.isContent = 1;
    }
  }
  if(dispReadOnlyGlobal.isExp == 0){
    dispReadOnlyGlobal.expPath[0] = '.';
    dispReadOnlyGlobal.expPath[1] = 0;
  }
  loadConfig(&configInfo); // get store config infomation
  strcpy(dispReadOnlyGlobal.devName, configInfo.devName);
  strcpy(dispReadOnlyGlobal.filePath, configInfo.jsonPath);

  if(initDispGlobalValue()){
    printf("System error\n");
    return 0;
  }
  v = chdir(dispReadOnlyGlobal.expPath);
  if(v){  // check export path
    printf("Wrong exp path %s\n", dispReadOnlyGlobal.expPath);
    return 0;
  }
  if(dispReadOnlyGlobal.isExp)
    vExp = openExpFile();
  v = chdir(dispReadOnlyGlobal.filePath);
  if(v){  // check file path
    printf("Wrong path %s\n", dispReadOnlyGlobal.filePath);
    return 0;
  }
  if(dispReadOnlyGlobal.devName[0] == 0){
    printf("Wrong device name\n");
    return 0;
  }
  getFileList();  // get the time period file
  readData();  // read data from file
  if((dispGlobalValue.cntValue == 0) && (dispGlobalValue.cntValue6 == 0)){
    printf("No data\n");
    return 0;
  }
  displayValue();  // display data of session
  displayBssValue();  // display session of http or db
  if(dispReadOnlyGlobal.isExp){
    if(vExp < 0){
      printf("Open exp file failed!\n");
      return 0;
    }
    expData(); // write data to export file
  }
  return 0;
}
