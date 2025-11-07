#!/bin/env bash

./build/pliney -log debug -runner-name fork \!\> target cnn.com 80 =\> transport tcp =\> lua "test/data/http.lua" | grep 'Response: .*Moved' 1>/dev/null
