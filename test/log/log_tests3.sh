#!/bin/env bash

# Test single extension header
# dst
sudo build/pliney -runner-name packet \!\> source fd7a:115c:a1e0::5fa2:3b13 4321  =\> target ::1 53 =\> transport udp =\> diffserv af41 =\> cong ect1 =\> hoplimit 27 =\> body test/data/dns_cnn =\> exthdr-padn dst 4 ab =\> log -mode overwrite ${RUNNER_TEMP}/testing.pcap

diff test/data/log_tests3.pcap ${RUNNER_TEMP}/testing.pcap

result=$?

sudo rm -f ${RUNNER_TEMP}/testing.pcap

exit $result

