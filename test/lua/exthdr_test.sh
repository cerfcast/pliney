#!/bin/env bash

sudo ./build/pliney -log debug -runner-name fork \!\> target ::1 80  =\> transport udp =\> exthdr-padn hbh 4 ef =\> lua "test/data/exthdr-padn.lua" 

