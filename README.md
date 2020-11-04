# Tmarlin Cloud Traffic Probe
 ![Tmarlin_logo](https://tmarlin.oss-us-east-1.aliyuncs.com/Tmarlin_logo_github.png "Tmarlin_logo")
## Catalog
  * [Abstract](#abstract)
  * [Functions](#functions)
  * [Features](#features)
  * [Suitability](#suitability)
  * [Application Scenarios](#application-scenarios)
  * [Opensource Roadmap](#opensource-roadmap)
  * [Download](#download)
  * [Compiling project
](#compiling-project
)
  * [Deployment](#deployment)
  * [Performance Consumption](#performance-consumption)
  * [Free or Subscription](#free-or-subscription)
  * [License](#license)
  * [FAQ](#faq)
  * [Screenshot](#screenshot)
  * [Contact Us](#contact-us)
## Abstract
Tmarlin is used to unify traffic capture, indicator analysis, data distribution and traffic forwarding of cloud traffic and process information.

Why unify? Because too many security and O&M requirements require data from cloud traffic, however, no user is willing to implant probes with different functions, or high consumption, poor performance, or security and compatibility risks, into more and more lightweight workloads, so we hope that Tmarlin can unify these requirements.
## Functions
- Capture and analyze the network traffic of host in real time, and output about 40 indicators of traffic, packet, session and latency, and associate process information; analyze complete URL and SQL; all of the above are output by JSON;

- Real-time forwarding of Raw Packets, and can be stored as PCAP by Tmarlin at the receiving end; in order to reduce bandwidth pressure, traffic can also be FIFO stored in the host, and PCAP can be retrieved or replayed to the receiving end only when needed.

![Tmarlin_functions](https://tmarlin.oss-us-east-1.aliyuncs.com/Tmarlin_function_github.png "Tmarlin_functions")
## Features
- Pure C language program, ultra-small size, ultra-high performance, excellent compatibility, no third-party environment dependence; it can be used as cloud architecture basic software.
- Tmarlin's JSON can be connected to **data analysis tools such as ELK / Splunk / Graylog without coding to quickly generate various scenarios**, and it can also be connected to our Tdolphin  platform (open source soon).
- Enterprise-level commercial product quality; 30 status KPIs, 10 latency KQIs, all have been strictly verified by Wireshark. Automatically unpack VXLAN, GRE, support IPv6, RESTful.

## Suitability
It is suitable for node server, virtual machine and container based on general Linux version; it is suitable for private cloud and public cloud.

## Application Scenarios
Based on Tmarlin's JSON and PCAP, combined with analysis tools such as ES, a very rich cloud security and O&M functions can be realized.
- Cloud traffic visualization monitoring and abnormal traffic analysis;
- Micro-segmentation; Threat awareness;
- Cloud web security and audit (by HTTP/URL), Cloud DB security and audit (by SQL); 
- Cloud NPMD (Network Performance Monitoring and Diagnostics);
- Combined with Xplico, Wireshark, Cuckoo sandbox, it can achieve more fine-grained security check.

## Opensource Roadmap
We are tcpiplabs.com, and we focus on cloud-network integrated traffic data governance, visualization, and NPMD. We will open source three main products in the near future:
- **Tmarlin Cloud Traffic Probe**; for cloud traffic capture, analysis, distribution and backtracking. This is the Linux version, click here for Tmarlin for Windows.
- **Tdolphin Cloud Traffic Visualization Platform**; It is used to collect, manage and visually monitor the data from Tmarlin.
- **Twhale Network Traffic Monitoring Platform**; ultra-high performance IDC traffic capture, analysis, NPMD, visual monitoring platform.

## Compiling Project
1. CentOS/RedHat/Suse  
- Install compilation tools:  
`yum install gcc make`  
- Installation dependencies:   
`yum install libpcap-devel`  
- Compile:  
`cd tmarlin`  
`./configure`  
`make`  
`make install`  
2. Ubuntu/Debian  
- Install compilation tools:   
`apt-get install gcc make`  
- Installation dependencies:   
`apt-get install libpcap-dev`  
- Compile:  
`cd tmarlin`  
`./configure`  
`make`  
`make install`  

## Download
- [Binary Program](https://tmarlin.oss-us-east-1.aliyuncs.com/tmarlin "Binary Program")
- [Command Line Help](https://tmarlin.oss-us-east-1.aliyuncs.com/tmarlin_command_help.pdf "Command Line Help")
- User Guide
- KPI/KQI List

## Deployment
- Deploy on the node server; pay special attention to that since a Tmarlin can only capture one NIC, in order to avoid capturing errors, please list all NICs first to determine whether the captured object has traffic passing;
- When deployed in a virtual machine, just capture the working NIC;
- If you want to capture Docker traffic, it is recommended to deploy on the Host OS of Docker. Otherwise, please package Tmarlin into Docker first.

## Performance Consumption

## Free or Subscription
- Tmarlin's code and program are free for individual users, educational users and NGOs;
- If you are a hard-working startup like us, you can get all our products for free;
- Commercial users need to purchase subscription fees before they can use them legally.[Purchase link](https://www.tcpiplabs.com/productinfo/403743.html "Purchase link"). 

## License
- [GPL 3.0](https://github.com/tcpiplabs/tmarlin/blob/main/LICENSE "GPL 3.0")

## FAQ

## Screenshot
![Tmarlin_GIF](https://tmarlin.oss-us-east-1.aliyuncs.com/Tmarlin_GIF.gif "Tmarlin_GIF")

## Contact Us
Any questions or needs, please contact email: service@tcpiplabs.com
