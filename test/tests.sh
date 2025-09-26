#/bin/env bash

# Send an HTTP GET to cnn.com
sudo ./build/pliney -type stream -log debug \!\> body test/data/http_get =\> ttl 27  =\> target 151.101.195.5 80