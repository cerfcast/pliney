#!/bin/env bash

# Should result in a response from the local DNS server.
./build/pliney \!\> transport udp =\> body ./test/data/dns_cnn =\> target 127.0.0.53 53

# Should result in a response from the local DNS server.
sudo ./build/pliney -runner-name packet \!\> transport udp =\> body ./test/data/dns_cnn =\> target 127.0.0.53 53
