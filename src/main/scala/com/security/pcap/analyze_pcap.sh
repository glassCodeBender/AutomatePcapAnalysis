#!/bin/bash

clear

Set local
Call :GetUnixTime UNIX_TIME

firstDump = “raw_pcap%UNIX_TIME%.pcap”
fileName = “pcap%UNIX_TIME%.csv”
outResult = “out-sanitized%UNIX_TIME%.csv”

# Going to write to pcap file.
# will run this for a set amount of time. 
# Command to get start time start_time="$(date -u +%s)"

# Run for 35 seconds 
tcpdump -G 35 -w $firstDump -i eth1

echo pcaps captured by tcpdump stored at $firstDump

tshark -2 -r $1 -T fields -E header=y -E separator=, -E occurrence=a -E quote=d -e frame.time -e ip.version -e ip.id -e ip.len -e ip.proto -e ip.ttl -e ip.flagshttp.request.method" -e http.host -e http.request.version -e http.user_agent -ehttp.server -e http.response.code -e " http.response.phrase “ip.version==" > $fileName

sed '1s/\./_/g;1s/\([^,\n]\{1,\}\)/"\1"/g' $outResult > $outResult

echo CSV from tshark stored in $outResult

scala analyze_pcap.jar $outResult
