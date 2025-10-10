#!/bin/env bash

./build/pliney -type dgram  \!\> body ./test/data/dns_cnn =\> target 8.8.8.8 53  =\> log  -mode overwrite ${RUNNER_TEMP}/testing.pcap

dd bs=1 skip=68 if=${RUNNER_TEMP}testing.pcap > ${RUNNER_TEMP}/testing.pcap.slim 
diff test/data/dns_cnn ${RUNNER_TEMP}/testing.pcap.slim

result=$?

rm -f ${RUNNER_TEMP}/testing.pcap
rm -f ${RUNNER_TEMP}/testing.pcap.slim

exit $result