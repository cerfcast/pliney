#!/bin/env bash

line_count=`sudo ./build/pliney -log debug -runner-name fork \!\> target ::1 80  =\> transport udp =\> exthdr-padn hbh 4 ef =\> exthdr-padn dst 4 aa =\> lua "test/data/exthdr-padn.lua" | grep 'Send result: 29' | wc -l`

if [ ${line_count} -ne 10 ]; then
				exit 1
fi
exit 0
