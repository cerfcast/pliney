#!/bin/env bash

./build/pliney -type dgram  \!\> body ./test/data/dns_cnn =\> target 8.8.8.8 53  =\> log  -mode overwrite /tmp/testing.pcap

dd bs=1 skip=68 if=/tmp/testing.pcap > /tmp/testing.pcap.slim 
diff test/data/dns_cnn /tmp/testing.pcap.slim

result=$?

rm -f /tmp/testing.pcap
rm -f /tmp/testing.pcap.slim

exit $result