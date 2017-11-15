#!/bin/bash

clear

# I have a feeling this could be wrong because I used Windows batch file code. 

Call :GetUnixTime UNIX_TIME

firstDump = “raw_pcap%UNIX_TIME%.tcpdump”
fileName = “pcap%UNIX_TIME%.csv”

export $firstDump
export $fileName

# If the directory already doesn’t exist, make it. 
mkdir Documents/pcaps

# Add filename info to file 
cat “Documents/pcaps/$fileName” > Documents/pcaps/file_reads.txt 

# Going to write to pcap file.
# will run this for a set amount of time. 
# Command to get start time start_time="$(date -u +%s)"

# Capture next 40,000 packets
tcpdump -c 40000 -w Documents/pcaps/$firstDump -i en1

# Organize data from pcap file into csv format.
tshark -2 -r Documents/pcaps/$firstDump -T fields -E header=y -E separator=/t -E occurrence=a -E quote=n -e frame.time -e ip.version -e ip.id -e ip.len -e ip.proto -e ip.ttl -e ip.flags -e ip.src -e ip.dst -e icmp.code -e icmp.type -e icmp.resptime -e udp.srcport -e udp.dstport -e dns.id -e dns.qry.type -e dns.resp.type -e dns.qry.name -e dns.a -e tcp.stream -e tcp.seq -e tcp.flags -e tcp.srcport -e tcp.dstport -e http.request.method -e http.host -e http.request.version -e http.user_agent -e http.server -e http.response.code -e http.response.phrase "ip.version==4" > Documents/pcaps/$fileName

scala analyze_pcap.jar

