#!/bin/env bash

./build/pliney -log debug -runner-name fork \!\> target 8.8.8.8 80 =\> transport udp =\> lua "test/data/sanity.lua" | grep 'udp{connected}: 0x' 1>/dev/null

