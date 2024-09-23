# dns-traffic-analysis
Tools for analyzing PCAP files to identify DNS queries with high latency.

# Overview
Clients frequently ask engineers to identify slow DNS queries in response to customer complaints about resolution issues. This often results in lengthy troubleshooting sessions using tools like tcpdump and Wireshark, along with extended customer interactions. The following tools can help streamline the investigation process and provide detailed reports directly from the CLI, reducing time spent on diagnostics.

* find-dns-server.py
  - read a pcap file and report on dns servers queried and their count
* traffic-analysis.py
  - read a pcap file and report on dns queries slower than the specified time duration
  - writes total queries and slow queries found to files for review
  - imports cProfile module for deeper dive into script internals
* dns-splitter.py
  - utilizes a query ID to seperate query and response packets from a larger pcap into a smaller file for review
* dns-packet-parser.py
  - reads pcap file and displays DNS packet content to stdout

## Requirements
 - Python 3.8 or higher.
 - [scapy](https://scapy.net/)
 - [tqdm](https://github.com/tqdm/tqdm)
 - [tcpdump](https://www.tcpdump.org/) pcap file

## Considerations
In the event a pcap file in extremely large, 100+ MB, consider breaking the file into smaller parts
```
tcpdump -r traffic.cap -w slow_queries -C 10M
```

## Additional tools that may be helpful
  - [wireshark](https://www.wireshark.org/)

## Recommended Setup 
### Clone repository
1. **Open your favorite terminal**
  - [Alacritty](https://alacritty.org/)
  - [iTerm2](https://iterm2.com/)
  - [Terminal](https://support.apple.com/guide/terminal/welcome/mac)
  - [List of Terminal Emulators](https://en.wikipedia.org/wiki/List_of_terminal_emulators)

2. **Clone [git](https://git-scm.com/doc) repository**
```
git clone https://github.com/mragusa/dns-traffic-analysis.git
```
3. **Change to dns-traffic-analysis directory**
```
cd ~/dns-traffic-analysis
```
### Create Python Virtual Environment
4. **Create python [venv](https://docs.python.org/3/library/venv.html) environment**
```
python3 -m venv venv
```
5. **Activate venv**
```
source ~/dns-traffic-analysis/venv/bin/activate
```
### Install required pip modules
6. **Install required modules**
```
pip install -r requirements.txt
```

## Usage
### find-dns-server.py
```
find-dns-server.py -h
usage: find_dns_server.py [-h] [-f FILE] [-p] [-d] [-c COUNT] [--focus {servers,recursive,clients}]

Parse pcap files to file DNS servers

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  pcap source file to parse
  -p, --profile         Enable CPU profiling
  -d, --display         display dns servers found
  -c COUNT, --count COUNT
                        display x amount of dns servers
  --focus {servers,recursive,clients}
                        Specify traffic to display

Identify DNS servers and clients from a PCAP file
```
#### Example
##### Find count of total DNS servers found
```
find-dns-server.py -f small_slow_packets
```
##### Output
```
Total DNS servers found: 686
Total recursive DNS servers found: 3
Total DNS clients found: 2022
```
##### Display DNS servers found
```
find-dns-server.py -f small_slow_packets -d --focus servers -c 10
```
##### Output
```
DNS Servers: 10.249.12.135 Count: 8308
DNS Servers: 193.108.88.128 Count: 71
DNS Servers: 216.239.34.10 Count: 59
DNS Servers: 192.42.93.30 Count: 58
DNS Servers: 150.171.10.240 Count: 39
DNS Servers: 23.44.98.133 Count: 35
DNS Servers: 10.247.10.20 Count: 34
DNS Servers: 199.253.249.53 Count: 34
DNS Servers: 192.5.5.241 Count: 34
DNS Servers: 13.107.222.201 Count: 28
```

### dns-packet-parser.py
```
dns-packet-parser.py -h
usage: dns-packet-parser.py [-h] -f FILE

Read a pcap file and display DNS packet fields.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the pcap file
```
#### Example
```
dns-packet-parser.py -f 38188.pcap
```

##### Output
```
Time: 18:31:12
Transaction ID: 38188
QR (Query/Response): Query
Opcode: 0
AA (Authoritative Answer): 0
TC (Truncated): 0
RD (Recursion Desired): 1
RA (Recursion Available): 0
Z (Reserved): 0
RCODE (Response Code): 0
QDCOUNT (Number of questions): 1
ANCOUNT (Number of answers): 0
NSCOUNT (Number of authority records): 0
ARCOUNT (Number of additional records): 0
Questions:
        Name: b'a6.sphotos.ak.fbcdn.net.'
        Type: 1
        Class: 1
==================================================
Time: 18:31:12
Transaction ID: 38188
QR (Query/Response): Response
Opcode: 0
AA (Authoritative Answer): 0
TC (Truncated): 0
RD (Recursion Desired): 1
RA (Recursion Available): 1
Z (Reserved): 0
RCODE (Response Code): 3
QDCOUNT (Number of questions): 1
ANCOUNT (Number of answers): 0
NSCOUNT (Number of authority records): 1
ARCOUNT (Number of additional records): 0
Questions:
        Name: b'a6.sphotos.ak.fbcdn.net.'
        Type: 1
        Class: 1
Authority Records:
        Name: b'fbcdn.net.'
        Type: 6
        TTL: 3426
==================================================
```

### dns-splitter.py
```
dns-splitter.py -h
usage: dns-splitter.py [-h] -p PCAP -d DNSID

Parse pcap files and seperate specific DNS Query IDs into new pcap file

options:
  -h, --help            show this help message and exit
  -p PCAP, --pcap PCAP  traffic capture file
  -d DNSID, --dnsid DNSID
                        dns query id

Uses query IDs found by traffic-analysis.py
```
#### Example
```
dns-splitter.py -p small_slow_packets -d 7368
```
##### Output
```
Opening file: small_slow_packets
Searching for Query ID: 7368
Transaction ID match found for 7368
Transaction ID match found for 7368
```
Output file: 7368.pcap

### traffic-analysis.py
```
traffic-analysis.py -h
usage: traffic-analysis.py [-h] [-f FILE] [-s SOURCE] [-t TIME] [-r REPORT] [-o OUTPUT] [-v]

Script to parse traffic capture files for slow queries

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Traffic Capture File (default: None)
  -s SOURCE, --source SOURCE
                        DNS Server IP Address (default: None)
  -t TIME, --time TIME  Latency delay measured in seconds (default: 0.5)
  -r REPORT, --report REPORT
                        Query Traffic Report Count (default: query_traffic_count.txt)
  -o OUTPUT, --output OUTPUT
                        Name of slow queries file output (default: slow_queries.txt)
  -v, --verbose         Verbose output (default: False)

This script will read a valid pcap file created by tcpdump and begin analysis to determine what DNS queries are slower that the provided timing (default 0.5 seconds aka 500ms. Upon analysis, the output of all slow
queries will be saved to a file in the following format query, query_id, latency. Wireshark can be used with the following filter: dns.id==<query_id> to filter the existing packet capture file to only show the latent
query in question. If a tcpdump file is too large and the desire is to break up the file into smaller segments for faster processing, the following command can be used: tcpdump -r <packet_capture> -w <new_file> -C
<size> example: tcpdump -r traffic.cap -w slow_queries -C 100. Processing ttime varies but a 100MB file takes about 10 mins
```
#### Example
```
traffic-analysis.py -f small_slow_packets -s 10.249.12.135
```
##### Output
```
Total packets found 46601 in small_slow_packets

Processing packets: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 46601/46601 [00:28<00:00, 1612.00packets/s]

Number of queries received: 10155
Number of responses sent: 6914

Processing Query Latency: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 10155/10155 [00:03<00:00, 2698.15queries/s]

Total Slow Queries: 3174
Saving slow queries to file

Processing Latency Times

Lowest Latency: -6.388747
Highest Latency: 7.313711
Median Latency: 1.0589565
Mean Latency: 1.425441996134518747584074217

Total Packets: 46601
Slow Queries: 3174
Percentage Difference: 93.18898736078624%

Saving Total Names Queried Report

Total Record Types Queried
Type: SOA Count: 810
Type: A Count: 6561
Type: PTR Count: 538
Type: HTTPS Count: 1470
Type: SRV Count: 108
Type: AAAA Count: 426
Type: SVCB Count: 118
Type: NS Count: 15
Type: URI Count: 2
Type: MX Count: 88
Type: CNAME Count: 15
Type: TXT Count: 1
Type: DS Count: 3
```


[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
