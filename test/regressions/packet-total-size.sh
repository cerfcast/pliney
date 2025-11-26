#!/bin/env bash

sudo ./build/pliney -runner-name packet \!\> transport icmp =\> icmp echo =\> target 8.8.8.8 =\> log -mode overwrite ${RUNNER_TEMP}/testing.pcap

diff test/data/regressions/packet-total-size.pcap ${RUNNER_TEMP}/testing.pcap

result=$?

sudo rm -f ${RUNNER_TEMP}/testing.pcap

exit $result
