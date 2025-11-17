#!/bin/env bash

sudo build/pliney -runner-name packet \!\> source fd7a:115c:a1e0::5fa2:3b13 4321  =\> target ::1 53 =\> transport udp =\> diffserv af41 =\> cong ect1 =\> hoplimit 27 =\> body test/data/dns_cnn =\> exthdr-padn hbh 4 af =\> exthdr-padn dst 4 ab =\> exthdr-padn hbh  6 fe =\> exthdr-padn dst 6 cd =\> log -mode overwrite ${RUNNER_TEMP}/testing.pcap

diff test/data/exthdr.pcap ${RUNNER_TEMP}/testing.pcap

result=$?

sudo rm -f ${RUNNER_TEMP}/testing.pcap

exit $result

