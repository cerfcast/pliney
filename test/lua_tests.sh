#!/bin/env bash

./build/pliney -log debug -runner-name lua \!\> target 8.8.8.8 80 =\> transport udp =\> meta LUA_SOURCE "test/data/sanity.lua" | grep 'udp{connected}: 0x' 1>/dev/null

