#!/bin/env bash

sudo ./build/pliney -runner-name packet \!\>   ttl 22 =\> transport udp =\> body test/data/dns_cnn =\> target 8.8.8.8 53 =\> error 1 8f =\> log -mode overwrite ${RUNNER_TEMP}/testing.pcap

diff test/data/all_error_dns.pcap ${RUNNER_TEMP}/testing.pcap

result=$?

#sudo rm -f ${RUNNER_TEMP}/testing.pcap

exit $result

